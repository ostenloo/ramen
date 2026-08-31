//! Handshake token handling (`01-protocol.md` §5, `04-guard.md` §4, §9).
//!
//! The supervisor's half of the handshake: deserialize the client's token,
//! verify its signature against the root **public** key, and extract the
//! `identity(...)` fact from the authority block (block 0). The raw base64
//! token string is what the connection carries to the guard: the guard
//! re-defends the root from the wire form independently (`04-guard.md` §9).
//!
//! Biscuit 6.x has no public API for reading individual facts, so the
//! identity is extracted from the authority block's datalog source
//! (`print_block_source(0)`), which is plain text of the form:
//!
//! ```datalog
//! identity("agent:planner");
//! capability("Whoami");
//! ```

use biscuit_auth::{Biscuit, PublicKey, UnverifiedBiscuit};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    /// The token string is not valid base64 or not a well-formed Biscuit
    /// token. Terminal: `Fault(MalformedRequest)`.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// The signature does not verify against the root public key. Terminal:
    /// `Fault(MalformedRequest)` — the supervisor does not disclose whether
    /// the token is parseable or the key is wrong.
    #[error("token failed signature verification")]
    InvalidSignature,
    /// The authority block carries no `identity("...")` fact. Terminal:
    /// `Fault(MalformedRequest)`.
    #[error("token has no identity fact")]
    MissingIdentity,
}

/// Verify a base64url (no padding) token against the root public key and
/// return its `identity(...)` value.
pub fn verify_token(token_b64: &str, root: &PublicKey) -> Result<String, TokenError> {
    let unverified = UnverifiedBiscuit::from_base64(token_b64)
        .map_err(|e| TokenError::Malformed(e.to_string()))?;
    let biscuit: Biscuit = unverified
        .verify(*root)
        .map_err(|_| TokenError::InvalidSignature)?;
    extract_identity(&biscuit)
}

/// Extract the `identity("...")` fact from block 0's source.
///
/// The root block is minted by `ramen-mint`, which emits the identity as a
/// string-literal fact; this parser handles that shape (one fact per line,
/// string without embedded quotes — the v0 identity grammar is
/// `agent:<name>` / `user:<name>`).
fn extract_identity(biscuit: &Biscuit) -> Result<String, TokenError> {
    let source = biscuit
        .print_block_source(0)
        .map_err(|e| TokenError::Malformed(format!("cannot read authority block: {e}")))?;
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("identity(") else {
            continue;
        };
        let Some(inner) = rest.strip_suffix(");") else {
            continue;
        };
        let inner = inner.trim();
        if inner.len() >= 2
            && inner.starts_with('"')
            && inner.ends_with('"')
            && !inner[1..inner.len() - 1].contains('"')
        {
            return Ok(inner[1..inner.len() - 1].to_string());
        }
    }
    Err(TokenError::MissingIdentity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{Algorithm, BiscuitBuilder, KeyPair};

    fn mint(root: &KeyPair, root_src: &str) -> String {
        BiscuitBuilder::new()
            .code(root_src)
            .unwrap()
            .build(root)
            .unwrap()
            .to_base64()
            .unwrap()
    }

    #[test]
    fn verifies_and_extracts_identity() {
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let b64 = mint(
            &root,
            "identity(\"agent:planner\");\ncapability(\"Whoami\");",
        );
        let identity = verify_token(&b64, &root.public()).unwrap();
        assert_eq!(identity, "agent:planner");
    }

    #[test]
    fn rejects_a_token_from_another_root() {
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let other = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let b64 = mint(&root, "identity(\"agent:a\");");
        let err = verify_token(&b64, &other.public()).unwrap_err();
        assert!(matches!(err, TokenError::InvalidSignature), "{err:?}");
    }

    #[test]
    fn rejects_garbage_base64() {
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let err = verify_token("not-base64!!", &root.public()).unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_valid_base64_garbage() {
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        // Valid base64 (three zero bytes) but not a Biscuit token.
        let b64 = "AAAA";
        let err = verify_token(b64, &root.public()).unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_a_token_without_an_identity_fact() {
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let b64 = mint(&root, "capability(\"Whoami\");");
        let err = verify_token(&b64, &root.public()).unwrap_err();
        assert!(matches!(err, TokenError::MissingIdentity), "{err:?}");
    }

    #[test]
    fn accepts_a_multi_block_token() {
        use biscuit_auth::BlockBuilder;

        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let b64 = mint(&root, "identity(\"agent:planner\");\ncapability(\"Whoami\");");
        // Append a delegation block (the check-only form used for
        // attenuation) with the same key → two blocks total.
        let token = UnverifiedBiscuit::from_base64(&b64).unwrap();
        let block = BlockBuilder::new()
            .code(r#"check if identity("agent:planner");"#)
            .unwrap();
        let attenuated = token.append_with_keypair(&root, block).unwrap();
        let b64_2 = attenuated.to_base64().unwrap();
        assert_eq!(attenuated.block_count(), 2);
        let identity = verify_token(&b64_2, &root.public()).unwrap();
        assert_eq!(identity, "agent:planner");
    }
}
