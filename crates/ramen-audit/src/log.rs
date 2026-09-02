//! The audit log: append-only, hash-chained, synchronously durable.
//!
//! # Architecture (`02-audit.md` §5, §7)
//!
//! - `AuditLog::open` verifies the full existing chain before accepting the
//!   log and recovers a torn tail (`§6`): truncate to the last valid frame,
//!   append a `TailTruncated` record. It refuses a chain-invalid log.
//! - The log is opened with an exclusive non-blocking `flock`; a second
//!   `open` on the same path fails while the first handle is alive.
//! - Appends go through a channel to a **dedicated blocking writer thread** —
//!   never the tokio runtime. The writer drains the queue (group commit),
//!   writes all pending frames, issues **one** `F_FULLFSYNC` per drain cycle,
//!   then replies to all waiters. `append` returns only after the record is
//!   durable.
//! - On any write/sync failure the log is dead: every in-flight waiter gets
//!   `Err`, remaining queued jobs are drained and failed, and all subsequent
//!   appends fail fast with [`AuditError::Closed`].
//! - Shutdown is [`AuditLog::close`]: it drains the writer queue (flush +
//!   `F_FULLFSYNC`) and joins the writer thread before returning. Dropping
//!   the handle does the same, best-effort.
//!
//! # Framing
//!
//! Frames are `u32` big-endian length prefix + canonical JSON — identical to
//! the wire protocol. This crate reuses `ramen_proto::encode` and
//! `ramen_proto::MAX_FRAME_BYTES` so there is exactly one framing
//! implementation in the system; the verifier does its own byte-level frame
//! walk (`verify::split_frames`) so a torn prefix mid-file produces a precise
//! finding instead of poisoning a streaming decode.
//!
//! # Known v0 gap
//!
//! A *clean* truncation — the file cut exactly at a frame boundary, dropping
//! whole records — is **undetectable in v0**: the surviving prefix is a
//! self-consistent chain. Only the `--from/--to` report range and operator
//! out-of-band knowledge mitigate it. This gap is pinned by a test
//! (`truncation_at_frame_boundary_is_undetectable`) and is a post-v0 concern
//! (e.g. signed checkpoints).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use ramen_proto::MAX_FRAME_BYTES;
use tokio::sync::oneshot;

use crate::chain::{genesis_hash, hex, next_hash};
use crate::ffullsync::{full_fsync, lock_exclusive};
use crate::record::{EventRecord, LogHeader, NewRecord, Record, RecordKind};
use crate::time::now_rfc3339;
use crate::verify::{verify_bytes, Severity};

/// Maximum record payload (frame body) size; frames are `MAX_FRAME_BYTES`
/// total, so records must fit in `MAX_FRAME_BYTES - 4`.
const MAX_RECORD_BYTES: usize = MAX_FRAME_BYTES as usize - 4;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AuditError {
    /// I/O failure, reported with the OS message (e.g. "Permission denied
    /// (os error 13)"). Kept as a `String` so the error can be fanned out to
    /// every waiter of a batch.
    #[error("audit log I/O error: {0}")]
    Io(String),
    #[error("framing error: {0}")]
    Framing(String),
    #[error("record serialization error: {0}")]
    Serialize(String),
    #[error("audit log is chain-invalid: {reason}")]
    ChainInvalid { reason: String },
    #[error("audit log is locked by another process")]
    Locked,
    #[error("audit log writer has terminated")]
    Closed,
    #[error("invalid record: {0}")]
    InvalidRecord(String),
    #[error("record too large: {0} bytes (max {MAX_RECORD_BYTES})")]
    RecordTooLarge(usize),
}

/// Chain position: the next `seq` to assign and `record_hash` of the last
/// frame written.
#[derive(Debug, Clone)]
pub(crate) struct ChainState {
    seq: u64,
    last_hash: [u8; 32],
}

pub(crate) struct Job {
    content: NewRecord,
    reply: oneshot::Sender<Result<u64, AuditError>>,
}

/// A hash-chained, append-only audit log with a group-commit writer thread.
///
/// `Clone` is deliberately not implemented: exactly one handle per process
/// per file (`02-audit.md` §5).
#[derive(Debug)]
pub struct AuditLog {
    tx: Option<mpsc::Sender<Job>>,
    worker: Option<thread::JoinHandle<Result<(), AuditError>>>,
    path: PathBuf,
}

impl AuditLog {
    /// Open (creating if absent) the audit log at `path`.
    ///
    /// `supervisor_version` is recorded in the `LogHeader` of newly created
    /// logs. The `02-audit.md` sketch shows `open(path)`, but the header
    /// requires the supervisor's version and no other source exists, so it is
    /// a parameter here.
    ///
    /// Refuses with [`AuditError::ChainInvalid`] if the existing log's chain
    /// is invalid, and [`AuditError::Locked`] if another process holds the
    /// file lock.
    pub fn open(path: &Path, supervisor_version: &str) -> Result<Self, AuditError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Append-only discipline: an existing file is never truncated;
            // recovery only ever shrinks a torn trailing fragment.
            .truncate(false)
            .open(path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        lock_exclusive(&file)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock => AuditError::Locked,
                _ => AuditError::Io(e.to_string()),
            })?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| AuditError::Io(e.to_string()))?;

        let report = verify_bytes(&bytes);
        // A torn *tail* produces critical findings without a seq (the
        // unparseable trailing fragment); those are recoverable by
        // truncating to the last complete frame (§6). A broken chain or a
        // corrupted complete frame produces findings tied to a seq and is
        // unrecoverable: refuse to open.
        if let Some(first) = report
            .findings
            .iter()
            .find(|f| f.severity == Severity::Critical && f.seq.is_some())
        {
            return Err(AuditError::ChainInvalid {
                reason: format!("seq {}: {}", first.seq.unwrap(), first.message),
            });
        }

        // Synchronous pre-writes (header / tail recovery) happen before the
        // writer thread starts, so the single-writer discipline holds: at
        // most one writer at any instant.
        let state = if bytes.is_empty() || report.record_count == 0 {
            // Fresh log — or only torn bytes with no complete frames, in
            // which case the header was never durable and the log never
            // existed. Recreate it fresh (the torn bytes are discarded; there
            // is nothing to record a `TailTruncated` about, because the
            // record that would carry it has no chain to ride on).
            if report.record_count == 0 && !bytes.is_empty() {
                file.set_len(0).map_err(|e| AuditError::Io(e.to_string()))?;
            }
            write_header(&mut file, supervisor_version)?
        } else if report.tail_bytes > 0 {
            // Torn tail: `02-audit.md` §6 recovery.
            let state = ChainState {
                seq: report.record_count as u64,
                last_hash: report.last_hash.expect("frames present"),
            };
            let tail = &bytes[report.last_valid_end..];
            file.set_len(report.last_valid_end as u64).map_err(|e| AuditError::Io(e.to_string()))?;
            let content = NewRecord {
                kind: RecordKind::TailTruncated,
                detail: serde_json::json!({
                    "bytes_discarded": tail.len(),
                    "sha256": hex(&sha256_of(tail)),
                }),
                ..NewRecord::new(RecordKind::TailTruncated)
            };
            let (frame, seq, h) = prepare_record(&state, &content)?;
            file.seek(SeekFrom::End(0)).map_err(|e| AuditError::Io(e.to_string()))?;
            file.write_all(&frame).map_err(|e| AuditError::Io(e.to_string()))?;
            file.sync_all().map_err(|e| AuditError::Io(e.to_string()))?;
            full_fsync(&file).map_err(|e| AuditError::Io(e.to_string()))?;
            ChainState { seq: seq + 1, last_hash: h }
        } else {
            // Valid, complete log: continue the chain.
            ChainState {
                seq: report.record_count as u64,
                last_hash: report.last_hash.expect("frames present"),
            }
        };

        let (tx, rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("ramen-audit-writer".into())
            .spawn(move || writer_loop(rx, file, state))
            .map_err(|e| AuditError::Io(e.to_string()))?;

        Ok(AuditLog {
            tx: Some(tx),
            worker: Some(worker),
            path: path.to_path_buf(),
        })
    }

    /// Append one record; returns its `seq` only after the record is durable
    /// (the writer's `F_FULLFSYNC` for the batch it landed in has completed).
    ///
    /// The log assigns `seq`, `ts`, and `prev_hash`; the caller supplies
    /// semantic content only. `kind == LogHeader` is rejected.
    pub async fn append(&self, record: &NewRecord) -> Result<u64, AuditError> {
        if record.kind == RecordKind::LogHeader {
            return Err(AuditError::InvalidRecord(
                "LogHeader is reserved for log creation".into(),
            ));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let tx = match &self.tx {
            Some(tx) => tx,
            None => return Err(AuditError::Closed), // already shut down
        };
        if tx
            .send(Job { content: record.clone(), reply: reply_tx })
            .is_err()
        {
            // Writer thread is gone: the channel is closed.
            return Err(AuditError::Closed);
        }
        match reply_rx.await {
            Ok(r) => r,
            Err(_) => Err(AuditError::Closed),
        }
    }

    /// Path this log was opened on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Drain the writer queue (the remaining jobs are written and durably
    /// synced), join the writer thread, and release the file lock.
    ///
    /// Returns the writer's terminal outcome; `Err` means the log died before
    /// shutdown completed (some appends may have failed — the audit trail up
    /// to the failure is intact and verifiable).
    pub fn close(mut self) -> Result<(), AuditError> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), AuditError> {
        // Idempotent: `close` consumes the handle, and `Drop` then runs
        // this same path — the second time everything is already taken.
        // Dropping the sender lets the writer drain what remains and exit.
        self.tx.take();
        let worker = match self.worker.take() {
            Some(worker) => worker,
            None => return Ok(()),
        };
        match worker.join() {
            Ok(r) => r,
            Err(_) => Err(AuditError::Closed), // writer thread panicked
        }
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        // Best-effort drain; the result is only observable through `close`.
        let _ = self.shutdown();
    }
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Build the `LogHeader` (record 0), write it durably, and return the chain
/// state to continue from.
fn write_header(file: &mut File, supervisor_version: &str) -> Result<ChainState, AuditError> {
    let log_id = ulid::Ulid::new().to_string();
    let genesis = genesis_hash(&log_id);
    let header = LogHeader {
        seq: 0,
        kind: RecordKind::LogHeader,
        log_id,
        created_at: now_rfc3339(),
        prev_hash: hex(&genesis),
        supervisor_version: supervisor_version.to_string(),
    };
    let mut frame = Vec::new();
    ramen_proto::encode(&Record::LogHeader(header), &mut frame)
        .map_err(|e| AuditError::Framing(e.to_string()))?;
    file.seek(SeekFrom::End(0)).map_err(|e| AuditError::Io(e.to_string()))?;
    file.write_all(&frame).map_err(|e| AuditError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| AuditError::Io(e.to_string()))?;
    full_fsync(file).map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(ChainState { seq: 1, last_hash: next_hash(&genesis, &frame) })
}

/// Serialize one event record with its chain fields and compute its hash.
/// Does not touch the file.
fn prepare_record(
    state: &ChainState,
    content: &NewRecord,
) -> Result<(Vec<u8>, u64, [u8; 32]), AuditError> {
    let seq = state.seq;
    let record = EventRecord {
        seq,
        ts: now_rfc3339(),
        prev_hash: hex(&state.last_hash),
        session: content.session,
        identity: content.identity.clone(),
        peer: content.peer.clone(),
        request_id: content.request_id,
        op_type: content.op_type.clone(),
        reversibility: content.reversibility,
        kind: content.kind,
        detail: content.detail.clone(),
        client: content.client.clone(),
    };
    let mut frame = Vec::new();
    match ramen_proto::encode(&Record::Event(record), &mut frame) {
        Ok(()) => {}
        Err(ramen_proto::CodecError::FrameTooLarge { declared, .. }) => {
            return Err(AuditError::RecordTooLarge(declared as usize));
        }
        Err(e) => return Err(AuditError::Serialize(e.to_string())),
    }
    let h = next_hash(&state.last_hash, &frame);
    Ok((frame, seq, h))
}

/// Write one prepared record to the file and advance the chain state.
fn write_record(
    file: &mut File,
    state: &mut ChainState,
    content: &NewRecord,
) -> Result<u64, AuditError> {
    let (frame, seq, h) = prepare_record(state, content)?;
    file.seek(SeekFrom::End(0)).map_err(|e| AuditError::Io(e.to_string()))?;
    file.write_all(&frame).map_err(|e| AuditError::Io(e.to_string()))?;
    state.seq = seq + 1;
    state.last_hash = h;
    Ok(seq)
}

/// The dedicated blocking writer thread.
///
/// Group commit: block on the first job, drain everything else that is
/// already queued, write all frames, issue ONE `sync_all` + `F_FULLFSYNC`
/// (one durability barrier per drain cycle, no matter the batch size), then
/// reply to every waiter. This is the property the "one F_FULLFSYNC per drain
/// cycle" test asserts by inspection.
pub(crate) fn writer_loop(
    rx: mpsc::Receiver<Job>,
    mut file: File,
    mut state: ChainState,
) -> Result<(), AuditError> {
    loop {
        let first = match rx.recv() {
            Ok(job) => job,
            // Sender dropped (close/drop) and the queue is drained.
            Err(mpsc::RecvError) => return Ok(()),
        };
        let mut batch = vec![first];
        while let Ok(job) = rx.try_recv() {
            batch.push(job);
        }

        let mut outcomes: Vec<Result<u64, AuditError>> = Vec::with_capacity(batch.len());
        let mut fatal: Option<AuditError> = None;
        let mut wrote_any = false;

        for job in batch.iter() {
            if let Some(e) = &fatal {
                outcomes.push(Err(e.clone()));
                continue;
            }
            match write_record(&mut file, &mut state, &job.content) {
                Ok(seq) => {
                    outcomes.push(Ok(seq));
                    wrote_any = true;
                }
                Err(e) => match e {
                    // I/O failure: the file may be corrupted mid-write — the
                    // writer stops and the log is dead.
                    AuditError::Io(_) => {
                        fatal = Some(e.clone());
                        outcomes.push(Err(e));
                    }
                    // Per-record rejection (oversize, malformed): this record
                    // is simply not written; the chain continues and the
                    // writer stays alive.
                    e => outcomes.push(Err(e)),
                }
            }
        }

        // One durability barrier per drain cycle.
        let sync_err = if wrote_any {
            match file.sync_all().and_then(|()| full_fsync(&file)) {
                Ok(()) => None,
                Err(e) => Some(AuditError::Io(e.to_string())),
            }
        } else {
            None
        };

        for (outcome, job) in outcomes.into_iter().zip(batch) {
            let final_outcome = match (&fatal, &sync_err) {
                (Some(e), _) | (None, Some(e)) => Err(e.clone()),
                (None, None) => outcome,
            };
            let _ = job.reply.send(final_outcome);
        }

        let fatal = fatal.or(sync_err);
        if let Some(e) = fatal {
            // The log is dead. Drain and fail everything still queued, then
            // exit; dropping `rx` closes the channel so any later send from
            // the supervisor fails immediately instead of hanging.
            while let Ok(job) = rx.try_recv() {
                let _ = job.reply.send(Err(e.clone()));
            }
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ramen-audit-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"").unwrap();
        path
    }

    /// A write failure must fail every waiter of the batch, exit the writer
    /// with that error, and poison the channel so later sends fail fast.
    #[test]
    fn writer_failure_fails_all_waiters_and_poisons_the_channel() {
        let path = tmp_file("ro.log");
        let file = std::fs::File::open(&path).unwrap(); // read-only: writes fail
        let (tx, rx) = mpsc::channel();
        let (t1, r1) = oneshot::channel();
        let (t2, r2) = oneshot::channel();
        tx.send(Job { content: NewRecord::new(RecordKind::Denied), reply: t1 }).unwrap();
        tx.send(Job { content: NewRecord::new(RecordKind::Denied), reply: t2 }).unwrap();

        let handle = std::thread::spawn(move || {
            writer_loop(rx, file, ChainState { seq: 1, last_hash: [0u8; 32] })
        });

        let e1 = futures::executor::block_on(r1).unwrap().unwrap_err();
        let e2 = futures::executor::block_on(r2).unwrap().unwrap_err();
        assert!(matches!(e1, AuditError::Io(_)), "{e1:?}");
        assert!(matches!(e2, AuditError::Io(_)), "{e2:?}");

        let writer_err = handle.join().unwrap().unwrap_err();
        assert!(matches!(writer_err, AuditError::Io(_)), "{writer_err:?}");

        // The writer dropped its receiver: the next send fails immediately.
        let (t3, _r3) = oneshot::channel();
        assert!(
            tx.send(Job { content: NewRecord::new(RecordKind::Denied), reply: t3 }).is_err(),
            "channel must be closed after a fatal writer error"
        );
    }
}
