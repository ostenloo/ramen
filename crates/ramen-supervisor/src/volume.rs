//! Startup volume checks (`05-operations.md` M6, "On APFS and `clonefile`").
//!
//! `clonefile(2)` is copy-on-write but only on APFS, and only within a
//! single volume. Both requirements are verified **at startup** and a
//! violation is a startup refusal — not a fallback. A byte-copy fallback
//! has different cost and different failure modes, and a supervisor that
//! silently switches between them makes the `Trivial` classification a lie
//! under conditions nobody tested.
//!
//! - The state directory's filesystem must be APFS (the snapshots live
//!   there and are `clonefile` clones of write targets).
//! - Every configured `allowed_prefixes` entry that exists at startup must
//!   share a device id with the state directory (the snapshot and the target
//!   must be on the same volume).

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::platform::{device_id, fs_type};

#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("state_dir {0} is not on APFS (filesystem type: {1}); snapshots require clonefile(2)")]
    NotApfs(String, String),
    #[error("allowed prefix {0} is on a different device than state_dir {1} (clonefile does not cross volumes)")]
    CrossVolume(String, String),
    #[error("filesystem check failed: {0}")]
    Io(#[source] std::io::Error),
}

/// Verify the state directory and the configured allowed prefixes
/// (`05-operations.md` M6).
///
/// - `state_dir` must be on APFS.
/// - Each prefix that exists must share a device id with `state_dir`. A
///   prefix that does not exist is skipped (with a warning from the caller's
///   log): the per-request path check already requires the target's parent
///   to exist, so a missing prefix can never match.
pub fn check_startup_volumes(state_dir: &Path, prefixes: &[PathBuf]) -> Result<(), VolumeError> {
    let fstype = fs_type(state_dir).map_err(VolumeError::Io)?;
    if fstype != "apfs" {
        return Err(VolumeError::NotApfs(
            state_dir.to_string_lossy().into_owned(),
            fstype,
        ));
    }

    let state_dev = device_id(state_dir).map_err(VolumeError::Io)?;
    for p in prefixes {
        if !p.exists() {
            continue;
        }
        let dev = device_id(p).map_err(VolumeError::Io)?;
        if dev != state_dev {
            return Err(VolumeError::CrossVolume(
                p.to_string_lossy().into_owned(),
                state_dir.to_string_lossy().into_owned(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The temp dir (and therefore the test state dir) is on the same
    /// volume; a state dir and a prefix inside it must pass.
    #[test]
    fn same_volume_passes() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        assert!(
            check_startup_volumes(&state, &[work]).is_ok(),
            "same-volume state dir and prefix must pass"
        );
    }

    /// A state dir and a prefix on different volumes must be refused.
    /// (`/` and a `tempfile` dir are on different devices only when the
    /// temp dir lives on an extra volume; on a standard single-volume
    /// Mac they match, so this test compares the *mechanism* — two
    /// distinct device ids — via `/dev` (devfs) vs the temp dir.)
    #[test]
    fn cross_volume_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        // devfs is always a different device than the main volume.
        let res = check_startup_volumes(&state, &[PathBuf::from("/dev")]);
        assert!(
            matches!(res, Err(VolumeError::CrossVolume(_, _))),
            "/dev (devfs) vs main volume must be cross-volume: {res:?}"
        );
    }

    /// A state dir on a non-APFS filesystem is refused (`05-operations.md`
    /// M6 acceptance: "Startup refuses on a non-APFS state directory").
    /// `/dev` is devfs — always a different filesystem type than APFS — so
    /// this holds on every macOS host without mounting anything.
    #[test]
    fn non_apfs_state_dir_is_refused() {
        let res = check_startup_volumes(std::path::Path::new("/dev"), &[]);
        assert!(
            matches!(res, Err(VolumeError::NotApfs(_, _))),
            "devfs state dir must be refused: {res:?}"
        );
    }

    /// A nonexistent prefix is skipped, not an error.
    #[test]
    fn missing_prefix_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let missing: PathBuf = dir.path().join("does-not-exist");
        assert!(check_startup_volumes(&state, &[missing]).is_ok());
    }
}
