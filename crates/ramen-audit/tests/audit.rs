//! M2 acceptance tests for `ramen-audit` (`02-audit.md`).
//!
//! Covers: chain integrity under tamper (byte flip, deletion, swap), torn-tail
//! recovery on re-open, the known clean-truncation gap (pinned), single-writer
//! locking, chain-invalid refusal, group commit (burst + threads), close/drop
//! drain, writer failure, and the `ramen-audit-verify` binary (exit codes,
//! `--json`, `--from`/`--to`).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ramen_audit::{
    split_frames, verify_bytes, AuditError, AuditLog, NewRecord, PeerInfo, RecordKind,
    Severity,
};
use ramen_proto::{Reversibility, RequestId, SessionId};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ramen-audit-test-{}-{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const VERSION: &str = "test-0.1.0";

fn log_path(dir: &Path) -> PathBuf {
    dir.join("audit.log")
}

fn open(dir: &Path) -> AuditLog {
    AuditLog::open(&log_path(dir), VERSION).unwrap()
}

fn append(log: &AuditLog, kind: RecordKind) -> u64 {
    futures::executor::block_on(log.append(&NewRecord::new(kind))).unwrap()
}

/// One clean authorization pair (checks 6/7 happy path): an `Authorized`
/// record with a verified peer and single-use request id, followed by its
/// `Executed` terminal record.
fn authorized_executed(log: &AuditLog, rid: RequestId) -> (u64, u64) {
    let session = SessionId::new();
    let auth = NewRecord {
        kind: RecordKind::Authorized,
        session: Some(session),
        identity: Some("agent:test".into()),
        peer: Some(PeerInfo {
            pid: 1234,
            signing_id: None,
            cdhash: Some("cdhash-test".into()),
            verified: true,
        }),
        request_id: Some(rid),
        op_type: Some("Whoami".into()),
        reversibility: Some(Reversibility::Trivial),
        ..NewRecord::new(RecordKind::Authorized)
    };
    let a = futures::executor::block_on(log.append(&auth)).unwrap();
    let exec = NewRecord {
        kind: RecordKind::Executed,
        session: Some(session),
        request_id: Some(rid),
        detail: serde_json::json!({ "op": "Whoami" }),
        ..NewRecord::new(RecordKind::Executed)
    };
    let e = futures::executor::block_on(log.append(&exec)).unwrap();
    (a, e)
}

type AppendFut = Pin<Box<dyn Future<Output = Result<u64, AuditError>>>>;

/// Build `count` in-flight append futures on `log` (each owns an `Arc`
/// clone of the log and its own record, so they are `'static`).
fn spawn_appends(log: &Arc<AuditLog>, count: usize) -> Vec<AppendFut> {
    (0..count)
        .map(|_| {
            let log = Arc::clone(log);
            let rec = NewRecord::new(RecordKind::Denied);
            Box::pin(async move { log.append(&rec).await }) as AppendFut
        })
        .collect()
}

/// Drive a set of in-flight append futures to completion with a no-op waker
/// (no runtime: the writer thread does the work; we just re-poll) and
/// return their seqs in sorted order.
fn drive_and_collect(pending: &mut Vec<AppendFut>) -> Vec<u64> {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut results: Vec<Option<Result<u64, AuditError>>> = vec![None; pending.len()];
    loop {
        let mut progress = false;
        for (i, f) in pending.iter_mut().enumerate() {
            if results[i].is_some() {
                continue;
            }
            if let Poll::Ready(r) = f.as_mut().poll(&mut cx) {
                results[i] = Some(r);
                progress = true;
            }
        }
        if results.iter().all(|r| r.is_some()) {
            break;
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut seqs: Vec<u64> = results.into_iter().map(|r| r.unwrap().unwrap()).collect();
    seqs.sort();
    seqs
}

// ---------------------------------------------------------------------------
// Basic lifecycle

#[test]
fn fresh_log_verifies_clean_and_seqs_start_at_one() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    assert_eq!(append(&log, RecordKind::SessionOpened), 1);
    assert_eq!(append(&log, RecordKind::Denied), 2);
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "clean log must have zero findings: {:?}", report.findings);
    assert_eq!(report.record_count, 3); // header + 2
    assert_eq!(report.last_valid_seq, Some(2));
}

#[test]
fn reopen_continues_the_chain() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for k in 1..=3 {
        assert_eq!(append(&log, RecordKind::Denied), k);
    }
    log.close().unwrap();

    let log = open(dir.path());
    assert_eq!(append(&log, RecordKind::SessionClosed), 4);
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "{:?}", report.findings);
    assert_eq!(report.record_count, 5);
}

#[test]
fn append_rejects_the_header_kind() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    let rec = NewRecord {
        kind: RecordKind::LogHeader,
        ..NewRecord::new(RecordKind::LogHeader)
    };
    let e = futures::executor::block_on(log.append(&rec)).unwrap_err();
    assert!(matches!(e, AuditError::InvalidRecord(_)), "{e:?}");
}

// ---------------------------------------------------------------------------
// Scale: 10,000 records verify clean

#[test]
fn ten_thousand_records_verify_clean() {
    let dir = TmpDir::new();
    let log = Arc::new(open(dir.path()));
    const WAVE: usize = 1000;
    for _ in 0..10 {
        let mut pending = spawn_appends(&log, WAVE);
        let seqs = drive_and_collect(&mut pending);
        assert_eq!(seqs.len(), WAVE);
    }
    let log = Arc::try_unwrap(log).unwrap();
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(
        report.status_code(),
        0,
        "10k log must verify clean: {:?}",
        report.findings
    );
    assert_eq!(report.record_count, 10_001);
    assert_eq!(report.last_valid_seq, Some(10_000));
}

// ---------------------------------------------------------------------------
// Tamper detection

#[test]
fn byte_flip_in_the_middle_fails_the_chain() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let mut bytes = std::fs::read(log_path(dir.path())).unwrap();
    let (s, e) = split_frames(&bytes).frames[5];
    bytes[s + 4 + (e - s - 4) / 2] ^= 0xFF;

    let report = verify_bytes(&bytes);
    assert_eq!(report.status_code(), 2);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "ChainMismatch" && f.severity == Severity::Critical),
        "expected ChainMismatch, got {:?}",
        report.findings
    );
}

#[test]
fn deleting_a_record_is_detected() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let bytes = std::fs::read(log_path(dir.path())).unwrap();
    let frames = split_frames(&bytes).frames;
    let (s, e) = frames[5];
    let mut tampered = bytes[..s].to_vec();
    tampered.extend_from_slice(&bytes[e..]);

    let report = verify_bytes(&tampered);
    assert_eq!(report.status_code(), 2);
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&"ChainMismatch"), "codes: {codes:?}");
    assert!(codes.contains(&"SeqBroken"), "codes: {codes:?}");
}

#[test]
fn swapping_adjacent_records_is_detected() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let bytes = std::fs::read(log_path(dir.path())).unwrap();
    let frames = split_frames(&bytes).frames;
    let (s4, e4) = frames[4];
    let (s5, e5) = frames[5];
    assert_eq!(e4, s5, "frames are contiguous");
    let mut tampered = Vec::new();
    tampered.extend_from_slice(&bytes[..s4]);
    tampered.extend_from_slice(&bytes[s5..e5]); // frame 5 first
    tampered.extend_from_slice(&bytes[s4..e4]); // then frame 4
    tampered.extend_from_slice(&bytes[e4..]);

    let report = verify_bytes(&tampered);
    assert_eq!(report.status_code(), 2);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "ChainMismatch" && f.severity == Severity::Critical),
        "got {:?}",
        report.findings
    );
}

// ---------------------------------------------------------------------------
// Truncation: torn tail recovers, clean cut is the pinned v0 gap

#[test]
fn torn_tail_is_recovered_on_reopen() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..8 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    // Cut the file in the middle of the last frame.
    let bytes = std::fs::read(log_path(dir.path())).unwrap();
    let split = split_frames(&bytes);
    let (s, e) = *split.frames.last().unwrap();
    let cut = s + 4 + (e - s - 4) / 2;
    std::fs::write(log_path(dir.path()), &bytes[..cut]).unwrap();

    // Re-open: recovery truncates to the last complete frame and records a
    // TailTruncated.
    let log = open(dir.path());
    assert_eq!(append(&log, RecordKind::SessionClosed), 9); // chain continues
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert!(
        !report.findings.iter().any(|f| f.severity == Severity::Critical),
        "no critical findings expected: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "TailTruncatedRecord"),
        "expected a TailTruncatedRecord warning: {:?}",
        report.findings
    );
    assert_eq!(report.record_count, 10); // header + 8 + TailTruncated + SessionClosed
    assert_eq!(report.status_code(), 1); // warnings only
}

#[test]
fn clean_truncation_at_frame_boundary_is_undetectable() {
    // KNOWN v0 GAP (pinned by this test): cutting the file exactly at a
    // frame boundary drops whole records, but the surviving prefix is a
    // self-consistent chain — no finding of any kind. Detection of this
    // case is a post-v0 concern (e.g. signed checkpoints / seq beacons).
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let bytes = std::fs::read(log_path(dir.path())).unwrap();
    let frames = split_frames(&bytes).frames;
    let (_, end) = frames[7]; // drop records 8, 9, 10 entirely
    let report = verify_bytes(&bytes[..end]);
    assert_eq!(report.status_code(), 0, "gap is pinned: {:?}", report.findings);
    assert!(report.findings.is_empty());
    assert_eq!(report.last_valid_seq, Some(7));
}

// ---------------------------------------------------------------------------
// Single writer / refusal

#[test]
fn second_open_while_locked_fails() {
    let dir = TmpDir::new();
    let _a = open(dir.path());
    let e = AuditLog::open(&log_path(dir.path()), VERSION).unwrap_err();
    assert!(matches!(e, AuditError::Locked), "{e:?}");
}

#[test]
fn open_refuses_a_chain_invalid_log() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let mut bytes = std::fs::read(log_path(dir.path())).unwrap();
    let (s, e) = split_frames(&bytes).frames[5];
    bytes[s + 4 + (e - s - 4) / 2] ^= 0xFF;
    std::fs::write(log_path(dir.path()), &bytes).unwrap();

    let e = AuditLog::open(&log_path(dir.path()), VERSION).unwrap_err();
    assert!(matches!(e, AuditError::ChainInvalid { .. }), "{e:?}");
}

// ---------------------------------------------------------------------------
// Group commit

#[test]
fn group_commit_burst_completes_all_waiters() {
    let dir = TmpDir::new();
    let log = Arc::new(open(dir.path()));
    const N: usize = 50;
    let mut pending = spawn_appends(&log, N);
    let seqs = drive_and_collect(&mut pending);
    assert_eq!(seqs, (1..=N as u64).collect::<Vec<_>>());
    let log = Arc::try_unwrap(log).unwrap();
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "{:?}", report.findings);
    assert_eq!(report.record_count, 1 + N);
}

#[test]
fn concurrent_appends_from_threads() {
    let dir = TmpDir::new();
    let log = Arc::new(open(dir.path()));
    const THREADS: usize = 4;
    const PER: usize = 5;
    let mut handles: Vec<std::thread::JoinHandle<Vec<u64>>> = Vec::new();
    for _ in 0..THREADS {
        let log = Arc::clone(&log);
        handles.push(std::thread::spawn(move || {
            (0..PER)
                .map(|_| futures::executor::block_on(log.append(&NewRecord::new(RecordKind::Denied))).unwrap())
                .collect()
        }));
    }
    let mut all: Vec<u64> = Vec::new();
    for h in handles {
        all.extend(h.join().unwrap());
    }
    all.sort();
    assert_eq!(all, (1..=(THREADS * PER) as u64).collect::<Vec<_>>());
    let log = Arc::try_unwrap(log).unwrap();
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "{:?}", report.findings);
}

#[test]
fn close_drains_queued_jobs() {
    let dir = TmpDir::new();
    let log = Arc::new(open(dir.path()));
    const N: usize = 500;
    // Submit N jobs (one poll each submits to the writer) and drop the
    // futures — close must still drain and durably write every record.
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut pending = spawn_appends(&log, N);
    for f in pending.iter_mut() {
        let _ = f.as_mut().poll(&mut cx);
    }
    drop(pending);
    let log = Arc::try_unwrap(log).unwrap();
    log.close().unwrap();

    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.record_count, 1 + N);
    assert!(
        !report.findings.iter().any(|f| f.severity == Severity::Critical),
        "{:?}",
        report.findings
    );
}

#[test]
fn drop_without_close_still_drains() {
    let dir = TmpDir::new();
    {
        let log = open(dir.path());
        for _ in 0..5 {
            append(&log, RecordKind::Denied);
        }
        // no close
    }
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.record_count, 6);
    assert!(
        !report.findings.iter().any(|f| f.severity == Severity::Critical),
        "{:?}",
        report.findings
    );
}

#[test]
fn oversize_record_is_rejected_and_the_log_survives() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    let big = "x".repeat(1_200_000);
    let rec = NewRecord {
        kind: RecordKind::Errored,
        detail: serde_json::json!({ "message": big }),
        ..NewRecord::new(RecordKind::Errored)
    };
    let e = futures::executor::block_on(log.append(&rec)).unwrap_err();
    assert!(matches!(e, AuditError::RecordTooLarge(_)), "{e:?}");

    // The writer is still alive: a normal append succeeds.
    assert_eq!(append(&log, RecordKind::Denied), 1);
    log.close().unwrap();
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "{:?}", report.findings);
}

// ---------------------------------------------------------------------------
// Authorization-invariant checks (verifier checks 6/7)

#[test]
fn authorized_pair_is_clean() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    authorized_executed(&log, RequestId::new());
    log.close().unwrap();
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert_eq!(report.status_code(), 0, "{:?}", report.findings);
}

#[test]
fn effect_without_authorization_is_critical() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    let rid = RequestId::new();
    let exec = NewRecord {
        kind: RecordKind::Executed,
        request_id: Some(rid),
        ..NewRecord::new(RecordKind::Executed)
    };
    append(&log, RecordKind::SessionOpened);
    futures::executor::block_on(log.append(&exec)).unwrap();
    log.close().unwrap();
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "EffectWithoutAuthorization" && f.severity == Severity::Critical),
        "{:?}",
        report.findings
    );
}

#[test]
fn unverified_authorization_is_critical() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    let auth = NewRecord {
        kind: RecordKind::Authorized,
        peer: Some(PeerInfo {
            pid: 1,
            signing_id: None,
            cdhash: None,
            verified: false,
        }),
        request_id: Some(RequestId::new()),
        ..NewRecord::new(RecordKind::Authorized)
    };
    append(&log, RecordKind::SessionOpened);
    futures::executor::block_on(log.append(&auth)).unwrap();
    log.close().unwrap();
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "UnverifiedAuthorization" && f.severity == Severity::Critical),
        "{:?}",
        report.findings
    );
}

#[test]
fn duplicate_authorization_is_critical() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    let rid = RequestId::new();
    for _ in 0..2 {
        let auth = NewRecord {
            kind: RecordKind::Authorized,
            peer: Some(PeerInfo {
                pid: 1,
                signing_id: None,
                cdhash: None,
                verified: true,
            }),
            request_id: Some(rid),
            ..NewRecord::new(RecordKind::Authorized)
        };
        futures::executor::block_on(log.append(&auth)).unwrap();
    }
    log.close().unwrap();
    let report = verify_bytes(&std::fs::read(log_path(dir.path())).unwrap());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "DuplicateAuthorization" && f.severity == Severity::Critical),
        "{:?}",
        report.findings
    );
}

// ---------------------------------------------------------------------------
// The ramen-audit-verify binary

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ramen-audit-verify"))
}

#[test]
fn bin_clean_exits_zero_with_json() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..5 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let out = Command::new(bin())
        .arg(log_path(dir.path()))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "stdout: {:?} stderr: {:?}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["records"].as_u64(), Some(6));
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn bin_tampered_exits_two() {
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..8 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let mut bytes = std::fs::read(log_path(dir.path())).unwrap();
    let (s, e) = split_frames(&bytes).frames[4];
    bytes[s + 4 + (e - s - 4) / 2] ^= 0xFF;
    std::fs::write(log_path(dir.path()), &bytes).unwrap();

    let out = Command::new(bin())
        .arg(log_path(dir.path()))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "failed");
    assert!(v["findings"].as_array().unwrap().iter().any(
        |f| f["code"] == "ChainMismatch"
    ));
}

#[test]
fn bin_range_filters_findings_but_chain_still_fails() {
    // Tamper at seq 5. A byte flip cascades: the hash of every later record
    // changes, so chain findings span seq 4 through the end. A report range
    // with no records in it (--from 20) therefore shows zero findings — yet
    // the exit code is still 2, because chain integrity is always verified
    // end-to-end; a local range is only meaningful over a verified chain.
    let dir = TmpDir::new();
    let log = open(dir.path());
    for _ in 0..10 {
        append(&log, RecordKind::Denied);
    }
    log.close().unwrap();

    let mut bytes = std::fs::read(log_path(dir.path())).unwrap();
    let (s, e) = split_frames(&bytes).frames[5]; // record seq 5
    bytes[s + 4 + (e - s - 4) / 2] ^= 0xFF;
    std::fs::write(log_path(dir.path()), &bytes).unwrap();

    let out = Command::new(bin())
        .arg(log_path(dir.path()))
        .arg("--json")
        .arg("--from")
        .arg("20")
        .arg("--to")
        .arg("25")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "chain integrity is global");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert_eq!(v["status"], "failed");
}

#[test]
fn bin_unreadable_exits_three() {
    let out = Command::new(bin())
        .arg("/nonexistent/ramen-audit-test.log")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}
