//! The root key: P-256 / secp256r1, verification only (`04-guard.md` §1, §3).
//!
//! Minting is an out-of-band operation performed by `ramen-mint`; a process
//! that can both verify and mint is one bug away from minting for itself.
//! The trait boundary is the deliverable — a `SecureEnclaveRootKey` will
//! implement the same trait later. The file backend is scaffolding.

use std::path::{Path, PathBuf};

use biscuit_auth::PublicKey;
use thiserror::Error;

/// Verification-only access to the root **public** key.
pub trait RootKey: Send + Sync {
    fn public_key(&self) -> PublicKey;
}

/// Loading a root key file from disk.
#[derive(Debug, Error)]
pub enum GuardError {
    #[error("reading root key file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("root key file {} is not a public key: {detail}", path.display())]
    NotPublicKey { path: PathBuf, detail: String },
    #[error("root key file {} is not a P-256/secp256r1 key (refusing non-P-256 roots)", path.display())]
    NotP256 { path: PathBuf },
}

/// P-256 public key loaded from a PEM file. Scaffolding (`04-guard.md` §3).
///
/// The root key MUST be P-256/secp256r1 (`04-guard.md` §3). biscuit's
/// `PublicKey::from_pem` happily parses Ed25519 keys too, so the curve is
/// checked here, not left to the token's signature scheme.
#[derive(Debug)]
pub struct FileRootKey {
    key: PublicKey,
}

impl FileRootKey {
    pub fn load(path: &Path) -> Result<Self, GuardError> {
        let pem = std::fs::read_to_string(path)
            .map_err(|source| GuardError::Io { path: path.to_path_buf(), source })?;
        let key = PublicKey::from_pem(&pem)
            .map_err(|e| GuardError::NotPublicKey { path: path.to_path_buf(), detail: e.to_string() })?;
        if !matches!(key, PublicKey::P256(_)) {
            return Err(GuardError::NotP256 { path: path.to_path_buf() });
        }
        Ok(Self { key })
    }
}

impl RootKey for FileRootKey {
    fn public_key(&self) -> PublicKey {
        self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{Algorithm, KeyPair};
    use tempfile::TempDir;

    fn write_pem(dir: &TempDir, name: &str, pem: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, pem).unwrap();
        p
    }

    #[test]
    fn loads_a_p256_public_key() {
        let dir = TempDir::new().unwrap();
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let p = write_pem(&dir, "root.pub", &kp.public().to_pem().unwrap().to_string());
        let key = FileRootKey::load(&p).unwrap();
        assert_eq!(key.public_key(), kp.public());
    }

    #[test]
    fn rejects_a_private_key_pem() {
        let dir = TempDir::new().unwrap();
        let kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let p = write_pem(&dir, "root.key", kp.to_private_key_pem().unwrap().as_ref());
        let err = FileRootKey::load(&p).unwrap_err();
        assert!(matches!(err, GuardError::NotPublicKey { .. }), "{err:?}");
    }

    #[test]
    fn rejects_garbage() {
        let dir = TempDir::new().unwrap();
        let p = write_pem(&dir, "root.pub", "not a pem at all");
        let err = FileRootKey::load(&p).unwrap_err();
        assert!(matches!(err, GuardError::NotPublicKey { .. }), "{err:?}");
    }

    #[test]
    fn missing_file_is_io() {
        let err = FileRootKey::load(Path::new("/nonexistent/ramen/root.pub")).unwrap_err();
        assert!(matches!(err, GuardError::Io { .. }), "{err:?}");
    }
}
