//! Framing: `u32` big-endian length prefix + UTF-8 JSON payload
//! (`01-protocol.md` §2).
//!
//! - [`encode`] appends one framed message to a byte buffer.
//! - [`Decoder`] accepts arbitrary chunk boundaries via [`Decoder::feed`] and
//!   yields complete frame payloads via [`Decoder::next_frame`].
//!
//! Oversize and zero-length prefixes are fatal and are rejected as soon as the
//! prefix is observed — *before any body bytes are buffered* — so a hostile or
//! buggy peer cannot use a bogus length to force unbounded buffering.

use std::collections::VecDeque;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Maximum frame payload size, in bytes (`01-protocol.md` §2).
pub const MAX_FRAME_BYTES: u32 = 1_048_576;

/// A fatal framing error. All variants terminate the connection; there is no
/// recovery state.
///
/// Note: no `PartialEq` — the `Json` payload (`serde_json::Error`) is neither
/// `PartialEq` nor `Eq`. Tests match on variants instead.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame of {declared} bytes exceeds the limit of {max}")]
    FrameTooLarge { declared: u32, max: u32 },
    #[error("zero-length frame")]
    ZeroLengthFrame,
    #[error("frame payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("frame payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append `msg` to `out` as one frame: 4-byte BE length prefix + JSON payload.
pub fn encode(msg: &impl serde::Serialize, out: &mut Vec<u8>) -> Result<(), CodecError> {
    let payload = serde_json::to_vec(msg).map_err(CodecError::Json)?;
    if payload.is_empty() {
        return Err(CodecError::ZeroLengthFrame);
    }
    let declared = payload.len() as u32;
    if declared > MAX_FRAME_BYTES {
        return Err(CodecError::FrameTooLarge { declared, max: MAX_FRAME_BYTES });
    }
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(())
}

/// Incremental frame decoder.
///
/// Feed it raw stream bytes in any chunk size; complete frames become
/// available through [`next_frame`](Decoder::next_frame). The decoder buffers
/// at most one partial frame plus completed frames awaiting pop, and rejects
/// an oversize prefix before buffering a single body byte.
///
/// After a [`CodecError`] the connection is dead; drop the decoder.
#[derive(Debug)]
pub struct Decoder {
    prefix: [u8; 4],
    prefix_len: usize,
    body: Vec<u8>,
    body_declared: u32,
    in_body: bool,
    frames: VecDeque<Vec<u8>>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            prefix: [0; 4],
            prefix_len: 0,
            body: Vec::new(),
            body_declared: 0,
            in_body: false,
            frames: VecDeque::new(),
        }
    }

    /// Ingest raw stream bytes. May complete zero or more frames.
    ///
    /// Returns `Err` as soon as an invalid prefix is observed; no body bytes
    /// for that frame are buffered.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        for &b in bytes {
            self.push_byte(b)?;
        }
        Ok(())
    }

    /// Pop the payload of the next complete frame, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        Ok(self.frames.pop_front())
    }

    /// Total bytes currently held by the decoder (partial frame body +
    /// completed frames awaiting pop). Exposed for backpressure monitoring and
    /// for the oversize-prefix test, which must verify that a rejected prefix
    /// buffered no body.
    pub fn buffered_len(&self) -> usize {
        self.body.len() + self.frames.iter().map(Vec::len).sum::<usize>()
    }

    fn push_byte(&mut self, b: u8) -> Result<(), CodecError> {
        if self.in_body {
            self.body.push(b);
            if self.body.len() == self.body_declared as usize {
                self.frames.push_back(std::mem::take(&mut self.body));
                self.in_body = false;
            }
            return Ok(());
        }

        self.prefix[self.prefix_len] = b;
        self.prefix_len += 1;
        if self.prefix_len == 4 {
            let declared = u32::from_be_bytes(self.prefix);
            self.prefix_len = 0;
            if declared == 0 {
                return Err(CodecError::ZeroLengthFrame);
            }
            if declared > MAX_FRAME_BYTES {
                // Reject before buffering any body bytes.
                self.body.clear();
                self.frames.clear();
                return Err(CodecError::FrameTooLarge { declared, max: MAX_FRAME_BYTES });
            }
            self.body_declared = declared;
            self.in_body = true;
        }
        Ok(())
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Duplicate-key detection
// ---------------------------------------------------------------------------
/// A serde visitor that walks any JSON value and rejects objects containing
/// duplicate keys at any depth.
///
/// serde_json's default behavior on duplicate keys is silent last-wins. The
/// protocol treats duplicate keys as a malformed request, so we detect them
/// explicitly (`01-protocol.md` §6: "A JSON payload with duplicate keys is
/// handled deterministically; assert the chosen behavior explicitly rather
/// than inheriting serde_json's default by accident").
#[derive(Debug)]
pub struct DuplicateKeyCheck;

impl<'de> Deserialize<'de> for DuplicateKeyCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DupCheckVisitor)
    }
}

/// The seed form of [`DuplicateKeyCheck`] for recursive map/seq walking.
struct DupCheckSeed;

impl<'de> DeserializeSeed<'de> for DupCheckSeed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(DupCheckVisitor).map(|_| ())
    }
}

struct DupCheckVisitor;

impl<'de> Visitor<'de> for DupCheckVisitor {
    type Value = DuplicateKeyCheck;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen: Vec<String> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.iter().any(|k| k == &key) {
                return Err(<A::Error as de::Error>::custom(format!("duplicate key {key:?} in object")));
            }
            seen.push(key);
            map.next_value_seed(DupCheckSeed)?;
        }
        Ok(DuplicateKeyCheck)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while (seq.next_element_seed(DupCheckSeed)?).is_some() {}
        Ok(DuplicateKeyCheck)
    }

    fn visit_bool<E: de::Error>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_i64<E: de::Error>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_u64<E: de::Error>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_char<E: de::Error>(self, _v: char) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_str<E: de::Error>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_string<E: de::Error>(self, _v: String) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_bytes<E: de::Error>(self, _v: &[u8]) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_byte_buf<E: de::Error>(self, _v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        Deserialize::deserialize(deserializer)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(DuplicateKeyCheck)
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        Deserialize::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `v` (JSON) into a framed payload: 4-byte BE length + bytes.
    fn frame<T: serde::Serialize>(v: T) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&v, &mut out).unwrap();
        out
    }

    #[test]
    fn encode_layout() {
        // "hello" serializes to the 7-byte JSON string `"hello"`.
        let f = frame("hello");
        assert_eq!(&f[..4], &[0, 0, 0, 7]);
        assert_eq!(&f[4..], b"\"hello\"");
    }

    #[test]
    fn reject_zero_length_prefix() {
        let mut d = Decoder::new();
        let err = d.feed(&[0, 0, 0, 0]).unwrap_err();
        assert!(matches!(err, CodecError::ZeroLengthFrame));
    }

    #[test]
    fn reject_oversize_prefix_without_buffering_body() {
        let mut d = Decoder::new();
        // Declare 2 MiB, then offer 100 bytes of "body".
        let mut bytes = (2u32 * 1024 * 1024).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[b'x'; 100]);
        let err = d.feed(&bytes).unwrap_err();
        match err {
            CodecError::FrameTooLarge { declared, max } => {
                assert_eq!(declared, 2 * 1024 * 1024);
                assert_eq!(max, MAX_FRAME_BYTES);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        // The body must not have been buffered.
        assert_eq!(d.buffered_len(), 0);
        assert!(d.next_frame().unwrap().is_none());
    }

    #[test]
    fn reject_oversize_prefix_split_across_feeds() {
        let mut d = Decoder::new();
        let prefix = (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
        d.feed(&prefix[..2]).unwrap();
        let err = d.feed(&prefix[2..]).unwrap_err();
        assert!(matches!(err, CodecError::FrameTooLarge { .. }));
        assert_eq!(d.buffered_len(), 0);
    }

    #[test]
    fn prefix_split_at_1_3_2_2_3_1() {
        let f = frame("0123456789"); // 4-byte prefix + 10 bytes
        for split in [1, 3, 2, 2, 3, 1] {
            let mut d = Decoder::new();
            let mut i = 0;
            let mut consumed = 0;
            while i < f.len() {
                let n = (split + i) % 5 + 1; // vary chunk size
                let n = n.min(f.len() - i);
                d.feed(&f[i..i + n]).unwrap();
                i += n;
                consumed += n;
            }
            assert_eq!(consumed, f.len());
            let got = d.next_frame().unwrap().unwrap();
            assert_eq!(got, f[4..].to_vec());
            assert!(d.next_frame().unwrap().is_none());
        }
    }

    #[test]
    fn multiple_frames_in_one_feed() {
        let f1 = frame("0123456789");
        let f2 = frame("ab");
        let mut d = Decoder::new();
        d.feed(&[f1.clone(), f2.clone()].concat()).unwrap();
        assert_eq!(d.next_frame().unwrap().unwrap(), f1[4..].to_vec());
        assert_eq!(d.next_frame().unwrap().unwrap(), f2[4..].to_vec());
        assert!(d.next_frame().unwrap().is_none());
    }

    #[test]
    fn exact_max_size_frame_accepted() {
        // Decode side: a hand-built frame whose payload is exactly
        // MAX_FRAME_BYTES bytes (JSON array of digits). Feed in awkward chunks.
        let body: String = format!("[{}]", "1".repeat(MAX_FRAME_BYTES as usize - 2));
        assert_eq!(body.len(), MAX_FRAME_BYTES as usize);
        let mut f = (body.len() as u32).to_be_bytes().to_vec();
        f.extend(body.bytes());
        let mut d = Decoder::new();
        let mut i = 0;
        while i < f.len() {
            let n = 997.min(f.len() - i);
            d.feed(&f[i..i + n]).unwrap();
            i += n;
        }
        let got = d.next_frame().unwrap().unwrap();
        assert_eq!(got.len(), MAX_FRAME_BYTES as usize);

        // Encode side: a string of MAX-2 chars serializes to exactly MAX bytes
        // (the two quotes count toward the payload).
        let s = "1".repeat(MAX_FRAME_BYTES as usize - 2);
        let mut out = Vec::new();
        encode(&s, &mut out).unwrap();
        assert_eq!(out.len(), MAX_FRAME_BYTES as usize + 4);
    }

    #[test]
    fn max_plus_one_prefix_rejected() {
        let mut d = Decoder::new();
        let err = d.feed(&(MAX_FRAME_BYTES + 1).to_be_bytes()).unwrap_err();
        assert!(matches!(err, CodecError::FrameTooLarge { .. }));
    }
}
