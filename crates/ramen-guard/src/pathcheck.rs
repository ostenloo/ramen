//! Path safety checks for FileWrite targets (`04-guard.md` §6, §7).
//!
//! Any path-valued fact must be fully canonicalized **before** it enters the
//! the authorizer, and the canonical form must be what is executed on
//! (`04-guard.md` §6). The control-plane check runs on the canonicalized
//! target and **before any other check** (§7, invariant 5): it is checked in
//! the guard, not left to operation implementations, so adding an operation
//! cannot accidentally omit it.
//!
//! The allowed-prefix check is deliberately **not** here: it needs the
//! token's `allowed_prefix` facts and is evaluated by the guard after the
//! token's own checks have passed, so that a token missing the capability
//! classifies as `CapabilityNotGranted`, not `ConstraintViolated`.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use ramen_proto::messages::DenialCode;

use crate::fs::Fs;

/// Control-plane locations, canonicalized once at startup.
///
/// `files` are the configured file paths (socket, audit log, root key,
/// config); `file_parents` are the containing directories of those files;
/// `state_dir` is the state directory — its **entire subtree** is
/// control-plane state (`04-guard.md` §7).
#[derive(Debug)]
pub struct ControlPlanePaths {
    pub(crate) files: BTreeSet<PathBuf>,
    pub(crate) file_parents: BTreeSet<PathBuf>,
    pub(crate) state_dir: PathBuf,
}

impl ControlPlanePaths {
    /// Canonicalize the configured locations.
    ///
    /// A file that does not exist yet (the socket, before `bind`) is
    /// resolved as its canonical parent plus the file name; its parent must
    /// exist. `state_dir` must exist and be a directory.
    pub fn new(files: &[PathBuf], state_dir: &Path) -> std::io::Result<Self> {
        let mut files_set = BTreeSet::new();
        let mut file_parents = BTreeSet::new();
        for f in files {
            let resolved = if f.exists() {
                f.canonicalize()?
            } else {
                let parent = f
                    .parent()
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent"))?;
                let name = f
                    .file_name()
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
                parent.canonicalize()?.join(name)
            };
            if let Some(p) = resolved.parent() {
                if p != Path::new("/") {
                    file_parents.insert(p.to_path_buf());
                }
            }
            files_set.insert(resolved);
        }

        let state = state_dir.canonicalize().map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("state_dir {}: {e}", state_dir.display()),
            )
        })?;
        if !state.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("state_dir is not a directory: {}", state_dir.display()),
            ));
        }

        Ok(Self {
            files: files_set,
            file_parents,
            state_dir: state,
        })
    }

    /// Whether a canonicalized target resolves inside Ramen's own state
    /// (`04-guard.md` §7).
    pub fn contains(&self, canonical_target: &Path) -> bool {
        self.files.iter().any(|f| canonical_target == *f)
            || self.file_parents.iter().any(|p| canonical_target == *p)
            || path_within(&self.state_dir, canonical_target)
    }
}

/// Component-wise containment: `target` is inside `dir` or equal to it.
///
/// `std::path::Path::starts_with` is component-wise (not string-prefix), so
/// `/Users/austin/workspace-secrets` does **not** start with `/Users/austin/work`.
pub(crate) fn path_within(dir: &Path, target: &Path) -> bool {
    target.starts_with(dir)
}

/// The result of the FileWrite path-safety check.
pub(crate) enum PathCheck {
    /// `target` is canonical, the parent exists, the target is not
    /// control-plane state, and the final component is not a symlink.
    Ok(PathBuf),
    Deny { code: DenialCode, reason: String },
}

/// The safety steps of `04-guard.md` §6, with §7 (control-plane protection)
/// running first among the resolved-target checks. The allowed-prefix check
/// is applied by the guard, after the authorizer has allowed.
pub(crate) fn check_file_write_path(
    raw: &str,
    fs: &dyn Fs,
    control_plane: &ControlPlanePaths,
) -> PathCheck {
    // Step 1: absolute path.
    let p = Path::new(raw);
    if !p.is_absolute() {
        return PathCheck::Deny {
            code: DenialCode::ConstraintViolated,
            reason: "path must be absolute".into(),
        };
    }

    // Step 2: no `..` component, lexically, before touching the filesystem.
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return PathCheck::Deny {
            code: DenialCode::ConstraintViolated,
            reason: "path must not contain a '..' component".into(),
        };
    }

    // Step 3: resolve symlinks on the parent directory.
    let (parent, name) = match (p.parent(), p.file_name()) {
        (Some(par), Some(name)) => (par, name),
        _ => {
            return PathCheck::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "not a file path".into(),
            }
        }
    };
    let canon_parent = match fs.canonicalize(parent) {
        Some(c) => c,
        None => {
            return PathCheck::Deny {
                code: DenialCode::ConstraintViolated,
                reason: "path does not exist".into(),
            }
        }
    };
    let target = canon_parent.join(name);

    // §7: control-plane protection — before the prefix and symlink checks.
    // A symlinked final component is resolved here so that a link pointing
    // at control-plane state is caught (on the raw string the target is
    // invisible).
    let resolved = if fs.is_symlink(&target) {
        fs.canonicalize(&target).unwrap_or_else(|| target.clone())
    } else {
        target.clone()
    };
    if control_plane.contains(&resolved) {
        return PathCheck::Deny {
            code: DenialCode::ControlPlaneProtected,
            reason: "target is control-plane state".into(),
        };
    }

    // Step 5: final component is a symlink — categorical refusal.
    if fs.is_symlink(&target) {
        return PathCheck::Deny {
            code: DenialCode::ConstraintViolated,
            reason: "final path component is a symlink".into(),
        };
    }

    PathCheck::Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp() -> ControlPlanePaths {
        ControlPlanePaths {
            files: [
                PathBuf::from("/cp/sup.sock"),
                PathBuf::from("/cp/audit.log"),
                PathBuf::from("/cp/root.pub"),
                PathBuf::from("/cp/config.toml"),
            ]
            .iter()
            .cloned()
            .collect(),
            file_parents: [PathBuf::from("/cp")].into_iter().collect(),
            state_dir: PathBuf::from("/cp/state"),
        }
    }

    struct NoFs;
    impl Fs for NoFs {
        fn canonicalize(&self, _path: &Path) -> Option<PathBuf> {
            None
        }
        fn is_symlink(&self, _path: &Path) -> bool {
            false
        }
    }

    fn deny_code(r: &PathCheck) -> Option<DenialCode> {
        match r {
            PathCheck::Ok(_) => None,
            PathCheck::Deny { code, .. } => Some(*code),
        }
    }

    #[test]
    fn component_wise_prefix() {
        // The canonical component-wise test: a string-prefix check would
        // accept /Users/austin/workspace-secrets under /Users/austin/work.
        assert!(!path_within(
            Path::new("/Users/austin/work"),
            Path::new("/Users/austin/workspace-secrets/x.md")
        ));
        assert!(path_within(
            Path::new("/Users/austin/work"),
            Path::new("/Users/austin/work/x.md")
        ));
        assert!(path_within(Path::new("/work"), Path::new("/work")));
        assert!(!path_within(Path::new("/work"), Path::new("/other")));
    }

    #[test]
    fn non_absolute_is_rejected() {
        let r = check_file_write_path("relative/path.md", &NoFs, &cp());
        assert_eq!(deny_code(&r), Some(DenialCode::ConstraintViolated));
    }

    #[test]
    fn dotdot_is_rejected_lexically() {
        // NoFs can observe this: rejection happens before any fs call.
        let r = check_file_write_path("/work/../etc/passwd", &NoFs, &cp());
        assert_eq!(deny_code(&r), Some(DenialCode::ConstraintViolated));
    }

    #[test]
    fn control_plane_paths_are_protected_individually() {
        let c = cp();
        for target in [
            "/cp/sup.sock",
            "/cp/audit.log",
            "/cp/root.pub",
            "/cp/config.toml",
            "/cp/state",
            "/cp/state/snapshots/a.md",
            "/cp",
        ] {
            assert!(
                c.contains(Path::new(target)),
                "{target} must be control-plane protected"
            );
        }
        assert!(!c.contains(Path::new("/other/file.md")));
        assert!(!c.contains(Path::new("/cp-state-evil")));
    }
}
