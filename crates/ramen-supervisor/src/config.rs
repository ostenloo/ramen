//! Configuration (`03-supervisor.md` §2).
//!
//! TOML, path from `--config`, no default search path, no environment
//! overrides. The configuration determines the enforcement boundary, and the
//! environment of a privileged process is a weaker channel than a file with
//! known ownership and mode — so there is deliberately no env-var override.
//!
//! A group- or world-writable config file is a startup refusal: anyone who can
//! modify the enforcement boundary must not be able to modify it.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// The supervisor's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub socket_path: PathBuf,
    pub audit_path: PathBuf,
    pub root_key_path: PathBuf,
    pub state_dir: PathBuf,
    /// Supervisor-level bound on `FileWrite` targets (`05-operations.md` M6).
    ///
    /// The token's `allowed_prefix` facts grant the *capability*; this list
    /// is the outer bound the supervisor itself enforces, so a minted token
    /// can never reach outside it. It is also what the startup volume check
    /// verifies (`state_dir` and every prefix must share a device —
    /// `clonefile` does not cross volumes).
    ///
    /// An empty list means no `FileWrite` can ever succeed: the supervisor
    /// fails closed rather than default to "everywhere".
    pub allowed_prefixes: Vec<PathBuf>,
    /// Raw `SecRequirement` string; compiled once at startup (§4).
    pub peer_requirement: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    socket_path: PathBuf,
    audit_path: PathBuf,
    root_key_path: PathBuf,
    state_dir: PathBuf,
    /// Optional; defaults to empty (no FileWrite targets allowed).
    #[serde(default)]
    allowed_prefixes: Vec<PathBuf>,
    peer: RawPeer,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    requirement: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file: {0}")]
    Io(#[source] std::io::Error),
    #[error(
        "config file is group- or world-writable (mode {mode:#o}); refusing to start"
    )]
    InsecureMode { mode: u32 },
    #[error("config file is not owned by the current user (uid {uid})")]
    NotOwned { uid: u32 },
    #[error("config parse error: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("allowed_prefixes entry is not absolute: {0}")]
    RelativePrefix(PathBuf),
}

/// Load and validate the configuration at `path`.
///
/// Checks, in order: file exists and is readable; the file is **not**
/// group- or world-writable; the file is owned by the current user; the TOML
/// parses with no unknown fields.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let meta = std::fs::metadata(path).map_err(ConfigError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        if mode & 0o022 != 0 {
            return Err(ConfigError::InsecureMode { mode });
        }
        if meta.uid() != crate::platform::geteuid() {
            return Err(ConfigError::NotOwned { uid: meta.uid() });
        }
    }

    let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    let raw: RawConfig = toml::from_str(&text).map_err(ConfigError::Parse)?;

    for p in &raw.allowed_prefixes {
        if !p.is_absolute() {
            return Err(ConfigError::RelativePrefix(p.clone()));
        }
    }

    Ok(Config {
        socket_path: raw.socket_path,
        audit_path: raw.audit_path,
        root_key_path: raw.root_key_path,
        state_dir: raw.state_dir,
        allowed_prefixes: raw.allowed_prefixes,
        peer_requirement: raw.peer.requirement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("config.toml");
        fs::write(&p, body).unwrap();
        p
    }

    const BODY: &str = r#"
socket_path = "/tmp/ramen-test/sup.sock"
audit_path  = "/tmp/ramen-test/audit.log"
root_key_path = "/tmp/ramen-test/root.pub"
state_dir   = "/tmp/ramen-test/state"

[peer]
requirement = 'identifier "test"'
"#;

    #[test]
    fn parses_a_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(dir.path(), BODY);
        let c = load(&p).unwrap();
        assert_eq!(c.socket_path, PathBuf::from("/tmp/ramen-test/sup.sock"));
        assert_eq!(c.peer_requirement, "identifier \"test\"");
    }

    #[test]
    fn rejects_group_writable_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(dir.path(), BODY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o664)).unwrap();
        }
        let err = load(&p).unwrap_err();
        assert!(matches!(err, ConfigError::InsecureMode { .. }), "{err:?}");
    }

    #[test]
    fn rejects_world_writable_config() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(dir.path(), BODY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o606)).unwrap();
        }
        let err = load(&p).unwrap_err();
        assert!(matches!(err, ConfigError::InsecureMode { .. }), "{err:?}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(dir.path(), &format!("{BODY}\nrogue = 1\n"));
        let err = load(&p).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn rejects_missing_peer_table() {
        let dir = tempfile::tempdir().unwrap();
        let body = BODY.replace("[peer]\nrequirement = 'identifier \"test\"'", "");
        let p = write_config(dir.path(), &body);
        let err = load(&p).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn allowed_prefixes_default_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_config(dir.path(), BODY);
        let c = load(&p).unwrap();
        assert!(c.allowed_prefixes.is_empty());
    }

    #[test]
    fn parses_allowed_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        // Insert before the `[peer]` header so the key stays top-level.
        let body = BODY.replace("\n[peer]", "\nallowed_prefixes = [\"/Users/austin/work\"]\n\n[peer]");
        let p = write_config(dir.path(), &body);
        let c = load(&p).unwrap();
        assert_eq!(c.allowed_prefixes, vec![PathBuf::from("/Users/austin/work")]);
    }

    #[test]
    fn rejects_relative_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let body = BODY.replace("\n[peer]", "\nallowed_prefixes = [\"work\"]\n\n[peer]");
        let p = write_config(dir.path(), &body);
        let err = load(&p).unwrap_err();
        assert!(matches!(err, ConfigError::RelativePrefix(_)), "{err:?}");
    }
}
