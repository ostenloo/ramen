//! `FileWrite` acceptance tests (`05-operations.md` M6, "Acceptance
//! criteria").
//!
//! Each test starts a supervisor whose supervisor-level `allowed_prefixes`
//! cover a fixture `writes/` directory, mints a token whose
//! `allowed_prefix` fact covers the same directory, and exercises one
//! criterion. The audit is read back from the log file and the chain is
//! verified with the standalone verifier logic (`common::assert_chain_valid`).

mod common;

use base64::Engine;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use common::{Client, Fixture, Supervisor};
use ramen_audit::{Record, RecordKind};
use ramen_proto::messages::{DenialCode, ErrorCode, OpResult};
use ramen_proto::{FileWriteOp, Operation, WriteMode};

/// SHA-256 of `"hello"`.
const HELLO_SHA256: &str =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

/// A fixture with a `writes/` directory, canonicalized.
struct WriteFixture {
    fx: Fixture,
    /// The supervisor's `writes/` directory (canonical form).
    prefix: std::path::PathBuf,
}

impl WriteFixture {
    fn new() -> Self {
        let fx = Fixture::new();
        let dir = fx.parts.dir_path.join("writes");
        std::fs::create_dir_all(&dir).unwrap();
        let prefix = dir.canonicalize().unwrap();
        Self { fx, prefix }
    }

    fn dir(&self) -> &Path {
        &self.prefix
    }

    fn sup(&self) -> Supervisor {
        let requirement = format!("identifier \"{}\"", common::test_binary_identifier());
        let body = self.fx.parts.body_with_prefixes(&requirement, std::slice::from_ref(&self.prefix));
        Supervisor::start_with_body(&self.fx, &body)
    }

    /// A token with the `FileWrite` capability and an `allowed_prefix`
    /// fact covering `dir`.
    fn token(&self, sup: &Supervisor, identity: &str) -> String {
        sup.filewrite_token(identity, &self.prefix.to_string_lossy())
    }
}

fn write_op(path: &Path, content_b64: &str, mode: WriteMode) -> Operation {
    Operation::FileWrite(FileWriteOp {
        path: path.to_string_lossy().into_owned(),
        content_b64: content_b64.into(),
        mode,
    })
}

fn events(sup: &Supervisor) -> Vec<ramen_audit::EventRecord> {
    sup.audit_records()
        .into_iter()
        .filter_map(|r| match r {
            Record::Event(e) => Some(e),
            Record::LogHeader(_) => None,
        })
        .collect()
}

fn kind_for(
    events: &[ramen_audit::EventRecord],
    id: ramen_proto::RequestId,
    kind: RecordKind,
) -> Option<ramen_audit::EventRecord> {
    events
        .iter()
        .find(|e| e.request_id == Some(id) && e.kind == kind)
        .cloned()
}

/// Assert the response is `Ok(FileWriteResult)` and return it.
fn assert_filewrite_ok(
    resp: &ramen_proto::Response,
) -> (ramen_proto::RequestId, ramen_proto::messages::FileWriteResult) {
    match resp {
        ramen_proto::Response::Ok { id, result, .. } => match result {
            OpResult::FileWrite(f) => (*id, f.clone()),
            other => panic!("expected FileWriteResult, got {other:?}"),
        },
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn assert_error(resp: &ramen_proto::Response, code: ErrorCode) {
    match resp {
        ramen_proto::Response::Error { error, .. } => assert_eq!(error.code, code),
        other => panic!("expected Error/{code:?}, got {other:?}"),
    }
}

fn assert_denied(resp: &ramen_proto::Response, code: DenialCode) {
    match resp {
        ramen_proto::Response::Denied { denial, .. } => {
            assert_eq!(denial.code, code, "expected denial {code:?}");
        }
        other => panic!("expected Denied/{code:?}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Criterion: authorized `Create` on a nonexistent path succeeds.
// ---------------------------------------------------------------------------

#[test]
fn create_on_nonexistent_path_succeeds() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("new.txt");
    let (id, resp) = client.request(write_op(&target, "aGVsbG8=", WriteMode::Create));
    let (_, result) = assert_filewrite_ok(&resp);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
    assert_eq!(result.path, target.canonicalize().unwrap().to_string_lossy());
    assert_eq!(result.bytes_written, 5);
    assert_eq!(result.content_sha256, HELLO_SHA256);
    assert_eq!(result.restore.kind, ramen_proto::messages::RestoreKind::Snapshot);

    // Audit: Authorized → Executed, in order.
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    let authorized = kind_for(&events, id, RecordKind::Authorized).expect("Authorized");
    let executed = kind_for(&events, id, RecordKind::Executed).expect("Executed");
    assert_eq!(executed.seq, authorized.seq + 1);
    // The Authorized detail carries the content digest, not the content.
    let detail = &authorized.detail;
    assert_eq!(
        detail.get("content_sha256"),
        Some(&serde_json::Value::String(HELLO_SHA256.into()))
    );
    assert!(
        !detail.to_string().contains("hello"),
        "the content itself must never appear in the audit"
    );

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: authorized `Overwrite` writes content, returns a restore
// handle, and the snapshot at the handle contains the original bytes.
// ---------------------------------------------------------------------------

#[test]
fn overwrite_writes_and_snapshot_holds_original_bytes() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("note.md");
    std::fs::write(&target, b"original content").unwrap();

    let (id, resp) = client.request(write_op(
        &target,
        "bmV3IGNvbnRlbnQ=", // "new content"
        WriteMode::Overwrite,
    ));
    let (_, result) = assert_filewrite_ok(&resp);
    assert_eq!(std::fs::read(&target).unwrap(), b"new content");
    assert_eq!(result.bytes_written, 11);

    // The snapshot at the handle contains the original bytes.
    let snapshots_dir = sup.parts.state.join("snapshots");
    let snapshot_path = snapshots_dir.join(&result.restore.handle);
    assert!(snapshot_path.exists(), "snapshot must exist at the handle");
    assert_eq!(std::fs::read(&snapshot_path).unwrap(), b"original content");

    // Audit: Authorized (with snapshot path + content hash) → Executed.
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    let authorized = kind_for(&events, id, RecordKind::Authorized).expect("Authorized");
    let executed = kind_for(&events, id, RecordKind::Executed).expect("Executed");
    assert_eq!(executed.seq, authorized.seq + 1);
    let detail = &authorized.detail;
    assert_eq!(
        detail.get("snapshot_path"),
        Some(&serde_json::Value::String(
            snapshot_path
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        ))
    );
    // The Executed detail carries the restore handle.
    assert!(
        executed
            .detail
            .to_string()
            .contains(&result.restore.handle)
    );

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: `Create` on an existing path returns ExecutionFailed (O_EXCL)
// and does not modify the file.
// ---------------------------------------------------------------------------

#[test]
fn create_on_existing_path_fails_without_modifying() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("exists.txt");
    std::fs::write(&target, b"keep me").unwrap();
    let mtime_before = std::fs::metadata(&target).unwrap().modified().unwrap();

    let (id, resp) = client.request(write_op(&target, "aGVsbG8=", WriteMode::Create));
    assert_error(&resp, ErrorCode::ExecutionFailed);

    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    assert_eq!(
        std::fs::metadata(&target).unwrap().modified().unwrap(),
        mtime_before,
        "the existing file must be untouched (mtime included)"
    );

    // Audit: Authorized → ExecutionFailed (the decision was made).
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    let authorized = kind_for(&events, id, RecordKind::Authorized).expect("Authorized");
    let failed = kind_for(&events, id, RecordKind::ExecutionFailed).expect("ExecutionFailed");
    assert_eq!(failed.seq, authorized.seq + 1);
    assert!(
        !events.iter().any(|e| e.request_id == Some(id) && e.kind == RecordKind::Executed),
        "no Executed record may exist"
    );

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: `Overwrite` on a nonexistent path returns ExecutionFailed
// (clonefile fails at step 4); audit shows Authorized then ExecutionFailed;
// the target is not created.
// ---------------------------------------------------------------------------

#[test]
fn overwrite_on_nonexistent_path_fails_and_creates_nothing() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("ghost.txt");
    let (id, resp) = client.request(write_op(&target, "aGVsbG8=", WriteMode::Overwrite));
    assert_error(&resp, ErrorCode::ExecutionFailed);

    assert!(!target.exists(), "the target must not be created");

    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    let authorized = kind_for(&events, id, RecordKind::Authorized).expect("Authorized");
    let failed = kind_for(&events, id, RecordKind::ExecutionFailed).expect("ExecutionFailed");
    assert_eq!(failed.seq, authorized.seq + 1);
    // No snapshot: clonefile failed.
    let snapshots_dir = sup.parts.state.join("snapshots");
    let count = snapshots_dir
        .read_dir()
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(count, 0, "no snapshot may exist when clonefile fails");

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: a denied write leaves the target byte-identical and creates no
// snapshot; assert on mtime as well as content.
// ---------------------------------------------------------------------------

#[test]
fn denied_write_changes_nothing() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    // A token with the FileWrite capability but no allowed_prefix fact: the
    // authorizer allows (the policy checks only the grant facts) and the
    // guard's prefix check denies.
    let token = sup.token("agent:writer", &["FileWrite"]);
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("protected.txt");
    std::fs::write(&target, b"keep me").unwrap();
    let mtime_before = std::fs::metadata(&target).unwrap().modified().unwrap();

    let (id, resp) = client.request(write_op(
        &target,
        "aGVsbG8=",
        WriteMode::Overwrite,
    ));
    assert_denied(&resp, DenialCode::ConstraintViolated);

    assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    assert_eq!(
        std::fs::metadata(&target).unwrap().modified().unwrap(),
        mtime_before
    );

    // Denied: no Authorized record at all (the decision never allowed).
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    assert!(
        kind_for(&events, id, RecordKind::Authorized).is_none(),
        "a denial must not produce an Authorized record"
    );
    assert!(kind_for(&events, id, RecordKind::Denied).is_some());
    let snapshots_dir = sup.parts.state.join("snapshots");
    assert_eq!(snapshots_dir.read_dir().unwrap().count(), 0);

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: path outside the *supervisor's* configured prefix (but inside
// the token's prefix) → Denied/ConstraintViolated, no Authorized, no write.
// ---------------------------------------------------------------------------

#[test]
fn path_outside_supervisor_prefix_is_denied() {
    let fx = WriteFixture::new();
    // The supervisor's allowed prefix covers `writes/` only.
    let mut sup = fx.sup();
    // The token's prefix covers the whole fixture dir (the outer bound is
    // the supervisor's list, not the token's fact).
    let token = sup.filewrite_token("agent:writer", &fx.fx.parts.dir_path.to_string_lossy());
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    // A target inside the token's prefix but outside the supervisor's.
    let other = fx.fx.parts.dir_path.join("outside");
    std::fs::create_dir_all(&other).unwrap();
    let target = other.join("escape.txt");

    let (id, resp) = client.request(write_op(&target, "aGVsbG8=", WriteMode::Create));
    assert_denied(&resp, DenialCode::ConstraintViolated);

    assert!(!target.exists());
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    assert!(kind_for(&events, id, RecordKind::Authorized).is_none());
    assert!(kind_for(&events, id, RecordKind::Denied).is_some());

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: `path` targeting the audit log → Denied/ControlPlaneProtected.
// ---------------------------------------------------------------------------

#[test]
fn audit_path_is_control_plane_protected() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    // The control-plane check precedes the prefix check, so no prefix fact
    // is needed (and none is required to pass).
    let token = sup.token("agent:writer", &["FileWrite"]);
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    // The audit log exists and is inside no allowed prefix.
    let (id, resp) = client.request(write_op(
        &sup.audit,
        "aGVsbG8=",
        WriteMode::Overwrite,
    ));
    assert_denied(&resp, DenialCode::ControlPlaneProtected);

    assert!(kind_for(&events(&sup), id, RecordKind::Authorized).is_none());
    common::assert_chain_valid(&sup.audit);

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: final component is a symlink whose target is inside the
// allowed prefix → Denied/ConstraintViolated. The refusal is categorical.
// The symlink is created before the request (the race variant is covered by
// 04-guard.md §6 and not directly testable).
// ---------------------------------------------------------------------------

#[test]
fn symlink_final_component_inside_prefix_is_denied() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let real = fx.dir().join("real.md");
    std::fs::write(&real, b"real content").unwrap();
    let link = fx.dir().join("link.md");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let (id, resp) = client.request(write_op(&link, "aGVsbG8=", WriteMode::Overwrite));
    assert_denied(&resp, DenialCode::ConstraintViolated);

    assert_eq!(std::fs::read(&real).unwrap(), b"real content");
    assert!(kind_for(&events(&sup), id, RecordKind::Authorized).is_none());
    common::assert_chain_valid(&sup.audit);

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: final component is a symlink whose target is outside the
// prefix → Denied/ConstraintViolated.
// ---------------------------------------------------------------------------

#[test]
fn symlink_final_component_outside_prefix_is_denied() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    // A target outside the allowed prefix.
    let outside = fx.fx.parts.dir_path.join("outside.md");
    std::fs::write(&outside, b"outside content").unwrap();
    let link = fx.dir().join("escape-link.md");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let (_id, resp) = client.request(write_op(&link, "aGVsbG8=", WriteMode::Overwrite));
    assert_denied(&resp, DenialCode::ConstraintViolated);

    assert_eq!(std::fs::read(&outside).unwrap(), b"outside content");
    common::assert_chain_valid(&sup.audit);

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: symlinked parent directory resolving outside the allowed
// prefix → denied.
// ---------------------------------------------------------------------------

#[test]
fn symlinked_parent_outside_prefix_is_denied() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    // A real directory outside the prefix, reached through a symlink inside
    // the prefix.
    let real_dir = fx.fx.parts.dir_path.join("real_dir");
    std::fs::create_dir_all(&real_dir).unwrap();
    let link_dir = fx.dir().join("link_dir");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    let target = link_dir.join("f.md");
    std::fs::write(&target, b"content").unwrap();

    let (_id, resp) = client.request(write_op(&target, "aGVsbG8=", WriteMode::Overwrite));
    assert_denied(&resp, DenialCode::ConstraintViolated);

    assert_eq!(std::fs::read(&target).unwrap(), b"content");
    common::assert_chain_valid(&sup.audit);

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: content over 256 KiB → Error/MalformedRequest; no Authorized
// record.
// ---------------------------------------------------------------------------

#[test]
fn oversize_content_is_malformed() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let big = vec![b'a'; 256 * 1024 + 1];
    let b64 = base64::engine::general_purpose::STANDARD.encode(&big);
    let target = fx.dir().join("big.txt");

    let (id, resp) = client.request(write_op(&target, &b64, WriteMode::Create));
    assert_error(&resp, ErrorCode::MalformedRequest);

    assert!(!target.exists());
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    assert!(
        kind_for(&events, id, RecordKind::Authorized).is_none(),
        "a malformed request must not produce an Authorized record"
    );
    assert!(kind_for(&events, id, RecordKind::Errored).is_some());

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: invalid base64 → Error/MalformedRequest; no Authorized record.
// ---------------------------------------------------------------------------

#[test]
fn invalid_base64_is_malformed() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = fx.dir().join("bad.txt");
    let (id, resp) = client.request(write_op(&target, "not!base64!", WriteMode::Create));
    assert_error(&resp, ErrorCode::MalformedRequest);

    assert!(!target.exists());
    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    assert!(kind_for(&events, id, RecordKind::Authorized).is_none());
    assert!(kind_for(&events, id, RecordKind::Errored).is_some());

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: snapshot failure path — read-only snapshot directory. The
// target is unmodified and the audit shows Authorized then ExecutionFailed
// with no write attempted.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_failure_leaves_target_unmodified() {
    let fx = WriteFixture::new();
    let mut sup = fx.sup();
    let token = fx.token(&sup, "agent:writer");
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    // Make the snapshot directory read-only so clonefile fails.
    let snapshots_dir = sup.parts.state.join("snapshots");
    std::fs::set_permissions(&snapshots_dir, PermissionsExt::from_mode(0o555)).unwrap();

    let target = fx.dir().join("ro.txt");
    std::fs::write(&target, b"original").unwrap();
    let mtime_before = std::fs::metadata(&target).unwrap().modified().unwrap();

    let (id, resp) = client.request(write_op(
        &target,
        "bmV3",
        WriteMode::Overwrite,
    ));
    assert_error(&resp, ErrorCode::ExecutionFailed);

    assert_eq!(std::fs::read(&target).unwrap(), b"original");
    assert_eq!(
        std::fs::metadata(&target).unwrap().modified().unwrap(),
        mtime_before
    );

    common::assert_chain_valid(&sup.audit);
    let events = events(&sup);
    let authorized = kind_for(&events, id, RecordKind::Authorized).expect("Authorized");
    let failed = kind_for(&events, id, RecordKind::ExecutionFailed).expect("ExecutionFailed");
    assert_eq!(failed.seq, authorized.seq + 1);

    // Restore the permission so the temp dir can be cleaned up.
    std::fs::set_permissions(&snapshots_dir, PermissionsExt::from_mode(0o700)).unwrap();

    drop(client);
    sup.terminate_and_wait();
}

// ---------------------------------------------------------------------------
// Criterion: audit ordering — `Authorized` strictly precedes the snapshot
// and the write. Verified via the test hook that pauses after the
// `Authorized` record: at the moment the record is durable, no effect has
// happened yet. A SIGKILL at that point leaves a dangling `Authorized` with
// a valid chain (`02-audit.md` §8 crash window).
// ---------------------------------------------------------------------------

#[test]
fn authorized_precedes_effect_and_crash_window_leaves_dangling_authorized() {
    let fx = WriteFixture::new();
    let requirement = format!("identifier \"{}\"", common::test_binary_identifier());
    let body = fx.fx.parts.body_with_prefixes(&requirement, std::slice::from_ref(&fx.prefix));
    let mut sup = Supervisor::start_with_body_env(
        &fx.fx,
        &body,
        &[("RAMEN_TEST_PAUSE_AFTER_AUTHORIZED", "1")],
    );

    let target = fx.dir().join("crash.txt");
    std::fs::write(&target, b"original").unwrap();
    let token = sup.filewrite_token("agent:crash", &fx.prefix.to_string_lossy());
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let req = ramen_proto::Request::new(write_op(&target, "bmV3", WriteMode::Overwrite));
    let id = req.id;
    // Send without reading: the supervisor pauses after the Authorized
    // record, before the effect.
    client.send(&ramen_proto::Message::Request(req));

    // Wait until the Authorized record is durable in the log file.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = events(&sup);
        if kind_for(&events, id, RecordKind::Authorized).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Authorized never appeared in the audit log"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Ordering: the record is durable and *no effect has happened yet* —
    // the target is still the original bytes.
    assert_eq!(std::fs::read(&target).unwrap(), b"original");

    // Kill in the window. The chain must remain valid with a dangling
    // Authorized (no terminal record), and no snapshot may exist.
    sup.kill_and_wait();
    common::assert_chain_valid(&sup.audit);

    let events = events(&sup);
    assert!(
        kind_for(&events, id, RecordKind::Authorized).is_some(),
        "the Authorized record must be durable"
    );
    assert!(
        kind_for(&events, id, RecordKind::Executed).is_none()
            && kind_for(&events, id, RecordKind::ExecutionFailed).is_none(),
        "no terminal record may exist after a crash in the window"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
    let snapshots_dir = sup.parts.state.join("snapshots");
    assert_eq!(snapshots_dir.read_dir().unwrap().count(), 0);
}

// ---------------------------------------------------------------------------
// Criterion: TOCTOU by path-component swap. The guard checks the path at
// authorization time. Between `Authorized` and the effect, an agent with
// write access to an intermediate directory can swap the target's parent
// (move it aside and plant a symlink at the same path pointing at a
// different in-prefix directory). The effect must land in the directory
// that was pinned — never in the swapped-in one. Verified via the
// `RAMEN_TEST_PAUSE_AFTER_AUTHORIZED` window.
// ---------------------------------------------------------------------------

#[test]
fn symlink_swap_during_window_cannot_steer_the_write() {
    let fx = WriteFixture::new();
    let requirement = format!("identifier \"{}\"", common::test_binary_identifier());
    let body = fx.fx.parts.body_with_prefixes(&requirement, std::slice::from_ref(&fx.prefix));
    // 5-second window between the durable `Authorized` record and the effect.
    let mut sup = Supervisor::start_with_body_env(
        &fx.fx,
        &body,
        &[("RAMEN_TEST_PAUSE_AFTER_AUTHORIZED", "5")],
    );

    let dir = fx.dir();
    // The authorized target lives in `a/`; `b/` is a decoy directory with
    // its own content.
    let a = dir.join("a");
    std::fs::create_dir(&a).unwrap();
    let b = dir.join("b");
    std::fs::create_dir(&b).unwrap();
    std::fs::write(b.join("b.txt"), b"decoy").unwrap();

    let token = sup.filewrite_token("agent:swap", &fx.prefix.to_string_lossy());
    let mut client = Client::connect(&sup.socket);
    client.hello(&token);

    let target = a.join("f.txt");
    let req = ramen_proto::Request::new(write_op(&target, "aGVsbG8=", WriteMode::Create));
    let id = req.id;
    client.send(&ramen_proto::Message::Request(req));

    // Wait until `Authorized` is durable (the pin has already happened).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if kind_for(&events(&sup), id, RecordKind::Authorized).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Authorized never appeared in the audit log"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Swap the target's parent: move the real directory aside (still inside
    // the configured prefix) and plant a symlink at the same path pointing
    // at the decoy directory. Every path-string re-resolution of
    // `<prefix>/a/f.txt` from now on lands in `b/`.
    let a_real = dir.join("a-real");
    std::fs::rename(&a, &a_real).unwrap();
    std::os::unix::fs::symlink(&a_real, &a).unwrap();

    // The effect (after the 5-second window) must write through the pin.
    let resp = match client.recv() {
        Some(ramen_proto::Message::Response(r)) => r,
        other => panic!("expected Response, got {other:?}"),
    };
    assert_filewrite_ok(&resp);

    // The write landed in the pinned (original) directory...
    assert_eq!(std::fs::read(a_real.join("f.txt")).unwrap(), b"hello");
    // ...and the decoy directory is untouched — no path re-resolution may
    // have steered the write into `b/`.
    assert!(
        !b.join("f.txt").exists(),
        "the write must not land in the swapped-in directory"
    );
    assert_eq!(b.read_dir().unwrap().count(), 1);

    common::assert_chain_valid(&sup.audit);
    drop(client);
    sup.terminate_and_wait();
}
