//! Socket lifecycle (`03-supervisor.md` §3).
//!
//! The order of operations matters:
//!
//! 1. **Directory check first**: the containing directory must be owned by
//!    the supervisor's uid and not group/world-writable. A writable parent
//!    means the socket can be replaced regardless of its own mode.
//! 2. **Live-instance probe**: attempt `connect()` on the existing path. If
//!    it succeeds, another instance holds the socket — abort ("already
//!    running"). Blindly unlinking would let a second instance silently
//!    hijack the path.
//! 3. **Unlink stale socket** (only when the probe failed).
//! 4. `bind()`, then **immediately** `chmod 0600`, then use. Between `bind`
//!    and `chmod` the socket exists with the process umask; doing these in
//!    the other order leaves a window in which the socket has default
//!    permissions.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("socket path {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error(
        "socket directory {dir} is group- or world-writable (mode {mode:#o}); refusing to start"
    )]
    DirectoryInsecure { dir: PathBuf, mode: u32 },
    #[error("socket directory {dir} is not owned by the current user (uid {uid})")]
    DirectoryNotOwned { dir: PathBuf, uid: u32 },
    #[error("a supervisor is already listening on {0}")]
    AlreadyRunning(PathBuf),
}

use std::path::PathBuf;

/// Create the listening socket at `path`, per the lifecycle above.
///
/// The returned `UnixListener` is immediately usable for `accept()`.
pub fn listen(path: &Path) -> Result<std::os::unix::net::UnixListener, SocketError> {
    // 1. Directory check.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| {
        SocketError::Io(
            path.to_path_buf(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path has no parent directory",
            ),
        )
    })?;
    let dir_meta = std::fs::metadata(dir)
        .map_err(|e| SocketError::Io(path.to_path_buf(), e))?;
    let mode = dir_meta.mode();
    if mode & 0o022 != 0 {
        return Err(SocketError::DirectoryInsecure {
            dir: dir.to_path_buf(),
            mode,
        });
    }
    if dir_meta.uid() != crate::platform::geteuid() {
        return Err(SocketError::DirectoryNotOwned {
            dir: dir.to_path_buf(),
            uid: dir_meta.uid(),
        });
    }

    // 2. Live-instance probe.
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => return Err(SocketError::AlreadyRunning(path.to_path_buf())),
            // Connection refused / no listener: stale socket.
            Err(_) => {
                std::fs::remove_file(path)
                    .map_err(|e| SocketError::Io(path.to_path_buf(), e))?;
            }
        }
    }

    // 3+4. Bind, chmod 0600 before use.
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(|e| SocketError::Io(path.to_path_buf(), e))?;
    std::fs::set_permissions(path, PermissionsExt::from_mode(0o600))
        .map_err(|e| SocketError::Io(path.to_path_buf(), e))?;

    Ok(listener)
}

/// Unlink the socket path (after the listener is closed).
pub fn unlink(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("could not unlink socket {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_and_chmods_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sup.sock");
        let listener = listen(&p).unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        drop(listener);
        unlink(&p);
        assert!(!p.exists());
    }

    #[test]
    fn refuses_group_writable_directory() {
        let dir = tempfile::tempdir().unwrap();
        // tempfile dirs are 0700 by default; make it group-writable.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let p = dir.path().join("sup.sock");
        let err = listen(&p).unwrap_err();
        assert!(matches!(err, SocketError::DirectoryInsecure { .. }), "{err:?}");
    }

    #[test]
    fn detects_a_live_listener() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sup.sock");
        let listener = listen(&p).unwrap();
        let err = listen(&p).unwrap_err();
        assert!(matches!(err, SocketError::AlreadyRunning(_)), "{err:?}");
        drop(listener);
    }

    #[test]
    fn recovers_from_a_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sup.sock");
        {
            let listener = listen(&p).unwrap();
            drop(listener);
        }
        // The file remains; no process holds it.
        assert!(p.exists());
        let listener2 = listen(&p).unwrap();
        drop(listener2);
    }
}
