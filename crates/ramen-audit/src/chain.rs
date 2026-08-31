//! The hash chain (`02-audit.md` §3):
//!
//! ```text
//! record_hash[n]   = SHA-256(record_hash[n-1] || frame_bytes[n])
//! record_hash[-1]  = SHA-256(GENESIS_DOMAIN || log_id)
//! ```
//!
//! `frame_bytes[n]` is the *exact* on-disk frame: the 4-byte big-endian
//! length prefix plus the canonical JSON payload. The chain is computed over
//! bytes, not over parsed records, so any tamper — including re-serialization
//! with different field order — is caught.

use sha2::{Digest, Sha256};

/// Domain separation for the genesis hash.
pub const GENESIS_DOMAIN: &[u8; 22] = b"ramen.audit.genesis.v1";

/// `record_hash[-1]` — the anchor for `log_id`.
pub fn genesis_hash(log_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GENESIS_DOMAIN);
    h.update(log_id.as_bytes());
    h.finalize().into()
}

/// `record_hash[n]` given `record_hash[n-1]` and the exact frame bytes.
pub fn next_hash(prev: &[u8; 32], frame_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(frame_bytes);
    h.finalize().into()
}

/// Lowercase hex encoding of a hash (64 chars) — the `prev_hash` field form.
pub fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Strictly validate a 64-char lowercase hex hash.
pub fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic_and_domain_separated() {
        let a = genesis_hash("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let b = genesis_hash("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        let c = genesis_hash("01ARZ3NDEKTSV4RRFFQ69G5FA2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // The same log_id hashed without the domain must differ.
        let raw: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"01ARZ3NDEKTSV4RRFFQ69G5FAV");
            h.finalize().into()
        };
        assert_ne!(a, raw);
    }

    #[test]
    fn chain_depends_on_exact_frame_bytes() {
        let prev = genesis_hash("log");
        let h1 = next_hash(&prev, b"\x00\x00\x00\x05hello");
        let h2 = next_hash(&prev, b"\x00\x00\x00\x05hellp");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hex_round_trips() {
        let h = genesis_hash("x");
        let s = hex(&h);
        assert!(is_valid_hex_hash(&s));
        assert!(!is_valid_hex_hash(&s.to_uppercase()));
        assert!(!is_valid_hex_hash(&s[..63]));
    }
}
