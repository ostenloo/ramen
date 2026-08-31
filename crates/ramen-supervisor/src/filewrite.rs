//! The `FileWrite` effect (`05-operations.md` M6).
//!
//! Execution sequence (order is load-bearing; do not rearrange):
//!
//! 1. (guard, upstream) path canonicalized and checked.
//! 2. (dispatch, upstream) base64 decoded, 256 KiB cap enforced.
//! 3. (dispatch, upstream) audit `Authorized` — durable before any effect,
//!    including the snapshot.
//! 4. Snapshot (`Overwrite` only): `clonefile(target, snapshot_path)`.
//!    Failure → `WriteError::Snapshot`; **no write is attempted**.
//! 5. Write:
//!    - `Create`: `O_WRONLY|O_CREAT|O_EXCL, 0644`, write, `fsync` the file,
//!      `fsync` the directory.
//!    - `Overwrite`: temp file in the same directory, write, `fsync` the
//!      file, `rename` over the target, `fsync` the directory (the
//!      atomic-rename pattern: a crash leaves either the old or the new
//!      file, never a truncated one).
//! 6. (dispatch, upstream) audit `Executed`.
//!
//! The snapshot path is `<state_dir>/snapshots/<session>.<request>.<sanitized
//! basename>` — deterministic, so it can be recorded in the `Authorized`
//! record before the snapshot exists.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ramen_proto::messages::{RestoreHandle, RestoreKind, Reversibility, WriteMode};
use ramen_proto::{FileWriteOp, RequestId, SessionId};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::platform::clonefile;

/// Decoded-content cap, well under the 1 MiB frame limit
/// (`05-operations.md` M6).
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;

/// The outcome of a successful `FileWrite`.
#[derive(Debug)]
pub struct WriteOutcome {
    /// The canonicalized target path (what was actually written).
    pub canonical: String,
    pub bytes_written: u64,
    /// Hex-encoded SHA-256 of the content as written.
    pub content_sha256: String,
    pub restore: RestoreHandle,
    /// The snapshot file on disk (`Overwrite` only; `Create` has no prior
    /// content, so no snapshot file exists — the handle is still reported).
    pub snapshot: Option<PathBuf>,
}

/// Effect failures. Both are audited `ExecutionFailed` and answered
/// `Error/ExecutionFailed` (the `Authorized` record already exists, so the
/// pair is complete and the chain invariant holds).
#[derive(Debug, Error)]
pub enum WriteError {
    /// Step 4: the snapshot could not be taken. No write was attempted; the
    /// target is untouched.
    #[error("snapshot failed: {0}")]
    Snapshot(String),
    /// Step 5: the write failed.
    #[error("write failed: {0}")]
    Write(String),
}

/// Run the full effect for an authorized `FileWrite`.
///
/// `target` is the canonicalized path the guard checked; `content` is the
/// decoded bytes (already capped); `session`/`request` name the snapshot.
pub fn execute(
    target: &Path,
    content: &[u8],
    mode: WriteMode,
    session: SessionId,
    request: RequestId,
    snapshots_dir: &Path,
) -> Result<WriteOutcome, WriteError> {
    let content_sha256 = sha256_hex(content);
    let handle = snapshot_handle_name(target, session, request);

    match mode {
        WriteMode::Create => execute_create(target, content, &content_sha256, &handle),
        WriteMode::Overwrite => execute_overwrite(
            target,
            content,
            &content_sha256,
            &handle,
            request,
            snapshots_dir,
        ),
    }
}

/// `Create`: the kernel provides the atomic "fail if exists" via `O_EXCL`.
///
/// A failure mid-write leaves no partial file: it is unlinked (best effort)
/// so the observable state is exactly "the file does not exist".
fn execute_create(
    target: &Path,
    content: &[u8],
    content_sha256: &str,
    handle: &str,
) -> Result<WriteOutcome, WriteError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(target)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                WriteError::Write("target already exists (mode Create, O_EXCL)".into())
            }
            _ => WriteError::Write(format!("open: {e}")),
        })?;

    if let Err(e) = write_and_sync(&mut file, content) {
        // Best-effort cleanup of the partial new file; there is no prior
        // content to preserve.
        let _ = std::fs::remove_file(target);
        return Err(WriteError::Write(format!("write: {e}")));
    }
    if let Err(e) = fsync_dir(target.parent().unwrap_or(Path::new("/"))) {
        // The content is fully on disk; a lost directory fsync is logged
        // upstream, not a failed write.
        tracing::warn!("create: directory fsync failed: {e}");
    }

    Ok(WriteOutcome {
        canonical: target.to_string_lossy().into_owned(),
        bytes_written: content.len() as u64,
        content_sha256: content_sha256.to_string(),
        restore: RestoreHandle {
            kind: RestoreKind::Snapshot,
            // `Create` has no prior content: no snapshot file exists. The
            // handle names the created file (session.request.basename) so a
            // future `Restore` — or a human with the audit log — can find it;
            // the compensation is `unlink` of the target
            // (`05-operations.md` M6, reversibility table).
            handle: handle.to_string(),
            reversibility: Reversibility::Trivial,
        },
        snapshot: None,
    })
}

/// `Overwrite`: snapshot (step 4) then atomic-rename write (step 5).
fn execute_overwrite(
    target: &Path,
    content: &[u8],
    content_sha256: &str,
    handle: &str,
    request: RequestId,
    snapshots_dir: &Path,
) -> Result<WriteOutcome, WriteError> {
    let dir = target
        .parent()
        .ok_or_else(|| WriteError::Write("target has no parent directory".into()))?;

    // Step 4: the snapshot. Failure means no write is attempted — the
    // target must remain exactly as it was.
    let snapshot_path = snapshots_dir.join(handle);
    clonefile(target, &snapshot_path).map_err(|e| {
        WriteError::Snapshot(format!("clonefile {} → {}: {e}", target.display(), snapshot_path.display()))
    })?;

    // Preserve the target's permission bits on the replacement.
    let target_mode = std::fs::metadata(target)
        .map(|m| m.permissions().mode() & 0o0777)
        .unwrap_or(0o644);

    // Step 5: temp file in the same directory (same volume), written
    // fully and fsynced before the atomic rename.
    let basename = target
        .file_name()
        .map(|b| b.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = dir.join(format!(".{basename}.ramen-tmp.{request}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(target_mode)
        .open(&temp)
        .map_err(|e| WriteError::Write(format!("open temp: {e}")))?;

    if let Err(e) = write_and_sync(&mut file, content) {
        let _ = std::fs::remove_file(&temp);
        return Err(WriteError::Write(format!("write: {e}")));
    }
    if let Err(e) = std::fs::rename(&temp, target) {
        let _ = std::fs::remove_file(&temp);
        return Err(WriteError::Write(format!("rename: {e}")));
    }
    if let Err(e) = fsync_dir(dir) {
        // The rename already landed; a lost directory fsync is logged
        // upstream, not a failed write.
        tracing::warn!("overwrite: directory fsync failed: {e}");
    }

    // The snapshot remains on a failed write too (spec: "the log shows
    // Authorized followed by ExecutionFailed and the snapshot remains").
    // On success it is the restore point.

    Ok(WriteOutcome {
        canonical: target.to_string_lossy().into_owned(),
        bytes_written: content.len() as u64,
        content_sha256: content_sha256.to_string(),
        restore: RestoreHandle {
            kind: RestoreKind::Snapshot,
            handle: handle.to_string(),
            reversibility: Reversibility::Trivial,
        },
        snapshot: Some(snapshot_path),
    })
}

/// Write all bytes and `fsync` the file.
fn write_and_sync(file: &mut File, content: &[u8]) -> std::io::Result<()> {
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

/// `fsync` a directory (durable metadata: creates, renames, unlinks).
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let d = OpenOptions::new().read(true).open(dir)?;
    d.sync_all()
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The deterministic snapshot/restore-handle name:
/// `<session_id>.<request_id>.<sanitized basename>`.
///
/// The session id is supervisor-generated, so uniqueness does not depend on
/// the client at all (`01-protocol.md` §3 does not guarantee
/// cross-connection uniqueness of request ids). The basename is a
/// human-readable suffix only.
pub fn snapshot_handle_name(target: &Path, session: SessionId, request: RequestId) -> String {
    let basename = target
        .file_name()
        .map(|b| b.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{session}.{request}.{}", sanitize_basename(&basename))
}

/// Sanitize to `[A-Za-z0-9._-]`, truncating to 64 bytes
/// (`05-operations.md` M6 step 4).
pub fn sanitize_basename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let bytes = sanitized.as_bytes();
    let cut = bytes.len().min(64);
    // Every kept character is ASCII, so cutting at a byte boundary cannot
    // split a character.
    String::from_utf8_lossy(&bytes[..cut]).into_owned()
}

/// The `Authorized` record detail for a `FileWrite` decision
/// (`02-audit.md` M6): the write mode, the content digest (so the log shows
/// what was authorized to be written, without the content itself), and the
/// deterministic snapshot path (`null` for `Create`, which takes no
/// snapshot).
pub fn authorized_detail(
    fw: &FileWriteOp,
    content: &[u8],
    snapshot_path: Option<&Path>,
) -> serde_json::Value {
    serde_json::json!({
        "mode": fw.mode,
        "content_sha256": sha256_hex(content),
        "snapshot_path": snapshot_path.map(|p| p.to_string_lossy().into_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_outside_charset() {
        assert_eq!(sanitize_basename("notes.md"), "notes.md");
        assert_eq!(sanitize_basename("a b/c:d"), "a_b_c_d");
        assert_eq!(sanitize_basename("ok-name_v2.txt"), "ok-name_v2.txt");
    }

    #[test]
    fn sanitize_truncates_to_64_bytes() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_basename(&long).len(), 64);
    }

    #[test]
    fn handle_shape_is_session_request_basename() {
        let session = SessionId::new();
        let request = RequestId::new();
        let name = snapshot_handle_name(Path::new("/work/notes.md"), session, request);
        assert_eq!(
            name,
            format!("{session}.{request}.notes.md"),
            "handle must be <session>.<request>.<sanitized basename>"
        );
    }

    #[test]
    fn create_succeeds_on_missing_and_fails_on_existing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.txt");

        let s = SessionId::new();
        let r = RequestId::new();
        let out = execute(&target, b"hello", WriteMode::Create, s, r, dir.path()).unwrap();
        assert_eq!(out.bytes_written, 5);
        assert!(out.snapshot.is_none(), "Create has no snapshot file");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");

        // Second Create on the same path: O_EXCL refusal, target untouched.
        let before = std::fs::read_to_string(&target).unwrap();
        let err = execute(&target, b"other", WriteMode::Create, s, RequestId::new(), dir.path())
            .unwrap_err();
        assert!(matches!(err, WriteError::Write(_)), "{err:?}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            before,
            "existing file must not be modified"
        );
    }

    #[test]
    fn overwrite_snapshots_original_bytes_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let snapshots = dir.path().join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        let target = dir.path().join("f.txt");
        std::fs::write(&target, b"original").unwrap();

        let s = SessionId::new();
        let r = RequestId::new();
        let out = execute(&target, b"replaced", WriteMode::Overwrite, s, r, &snapshots).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "replaced");
        let snap = out.snapshot.as_ref().expect("Overwrite takes a snapshot");
        assert!(snap.exists(), "snapshot file must exist");
        assert_eq!(
            std::fs::read(snap).unwrap(),
            b"original",
            "snapshot must contain the ORIGINAL bytes"
        );
        assert_eq!(out.restore.handle, snap.file_name().unwrap().to_string_lossy());
        assert_eq!(
            out.content_sha256,
            format!("{:x}", Sha256::digest(b"replaced"))
        );
    }

    #[test]
    fn overwrite_on_missing_target_fails_at_snapshot_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        let snapshots = dir.path().join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        let target = dir.path().join("missing.txt");

        let err = execute(
            &target,
            b"x",
            WriteMode::Overwrite,
            SessionId::new(),
            RequestId::new(),
            &snapshots,
        )
        .unwrap_err();
        assert!(matches!(err, WriteError::Snapshot(_)), "{err:?}");
        assert!(!target.exists(), "the target must not be created");
    }

    #[test]
    fn overwrite_preserves_target_mode() {
        let dir = tempfile::tempdir().unwrap();
        let snapshots = dir.path().join("snapshots");
        std::fs::create_dir_all(&snapshots).unwrap();
        let target = dir.path().join("m.txt");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();

        execute(
            &target,
            b"new",
            WriteMode::Overwrite,
            SessionId::new(),
            RequestId::new(),
            &snapshots,
        )
        .unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o0777;
        assert_eq!(mode, 0o640, "overwrite must preserve the target's mode");
    }
}
