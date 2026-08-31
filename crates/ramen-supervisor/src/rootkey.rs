//! Root public key loading (`03-supervisor.md` §1, `04-guard.md` §3).
//!
//! The supervisor **verifies only**: it never holds minting capability. The
//! root *private* key lives in the minter (`ramen-mint`) and must never be
//! reachable from supervisor configuration. This module enforces that
//! boundary at startup: if `root_key_path` parses as a **private** key, the
//! supervisor refuses to start rather than silently ignoring the
//! misconfiguration. Biscuit 6.x key serialization differentiates the two
//! (SPKI vs PKCS#8), making the check a parse attempt in each direction.

use std::path::Path;

use biscuit_auth::{PublicKey, PrivateKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RootKeyError {
    #[error("root key file: {0}")]
    Io(#[source] std::io::Error),
    /// The file parses as a **private** key. Minting capability must never
    /// enter the supervisor.
    #[error(
        "{0} parses as a PRIVATE key; the supervisor only verifies. \
         Point root_key_path at the public key (root.pub), not the private key"
    )]
    ParsesAsPrivateKey(PathBuf),
    /// Neither a public nor a private key.
    #[error("{0} is not a valid Biscuit public key: {1}")]
    Invalid(PathBuf, String),
}

use std::path::PathBuf;

/// Load the root **public** key from `path`.
///
/// Order matters: try the public-key parse first (the normal case); only if
/// that fails, try the private-key parse to distinguish "a private key was
/// configured" (a specific, actionable refusal) from "not a key at all".
pub fn load_root_public_key(path: &Path) -> Result<PublicKey, RootKeyError> {
    let pem = std::fs::read_to_string(path).map_err(RootKeyError::Io)?;

    if let Ok(key) = PublicKey::from_pem(&pem) {
        return Ok(key);
    }
    if PrivateKey::from_pem(&pem).is_ok() {
        return Err(RootKeyError::ParsesAsPrivateKey(path.to_path_buf()));
    }
    Err(RootKeyError::Invalid(
        path.to_path_buf(),
        "not a Biscuit public or private key".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{Algorithm, KeyPair};

    #[test]
    fn loads_a_public_key() {
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("root.pub");
        std::fs::write(&p, kp.public().to_pem().unwrap()).unwrap();
        let key = load_root_public_key(&p).unwrap();
        assert_eq!(key, kp.public());
    }

    #[test]
    fn refuses_a_private_key() {
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("root.key");
        std::fs::write(&p, kp.to_private_key_pem().unwrap().as_str()).unwrap();
        let err = load_root_public_key(&p).unwrap_err();
        match err {
            RootKeyError::ParsesAsPrivateKey(p2) => assert_eq!(p2, p),
            other => panic!("expected ParsesAsPrivateKey, got {other:?}"),
        }
    }

    #[test]
    fn refuses_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bogus.pub");
        std::fs::write(&p, "not a key at all").unwrap();
        let err = load_root_public_key(&p).unwrap_err();
        assert!(matches!(err, RootKeyError::Invalid(_, _)), "{err:?}");
    }

    #[test]
    fn refuses_missing_file() {
        let err = load_root_public_key(std::path::Path::new("/nonexistent/root.pub")).unwrap_err();
        assert!(matches!(err, RootKeyError::Io(_)), "{err:?}");
    }
}
