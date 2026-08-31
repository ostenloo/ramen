//! Framing codec: u32 big-endian length prefix + payload (spec 01-protocol.md §2).
//!
//! This is an *independent* implementation: it was written from the spec text
//! alone and conformance is proven by the golden-fixture round-trip tests.

use std::collections::VecDeque;

/// Hard limit on frame size (spec §2, §6: 1 MiB).
pub const MAX_FRAME_BYTES: u32 = 1_048_576;

/// Frame-level (and decode) errors. Transport I/O errors are not in this
/// enum — the spec assigns transport failures to `SdkError` (§1, §8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A length prefix declared more than `MAX_FRAME_BYTES` bytes.
    #[error("frame size {declared} exceeds limit {max}")]
    FrameTooLarge { declared: u32, max: u32 },
    /// A zero-length prefix (ambiguous with "no data").
    #[error("zero-length frame")]
    ZeroLengthFrame,
    /// Frame payload is not valid UTF-8.
    #[error("frame payload is not valid UTF-8: {0}")]
    Utf8(String),
    /// Frame payload is not valid JSON.
    #[error("frame payload is not valid JSON: {0}")]
    Json(String),
}

/// Incremental frame decoder (spec §2 API).
///
/// `feed` returns `Err` immediately — before buffering any body bytes — when
/// an oversized or zero-length prefix is observed.
#[derive(Debug, Default)]
pub struct Decoder {
    /// Bytes of the frame currently being accumulated.
    buf: Vec<u8>,
    /// Remaining payload bytes expected, or `None` while reading the prefix.
    need: Option<usize>,
    /// Fully decoded frames, in order, waiting to be popped by `next_frame`.
    completed: VecDeque<Vec<u8>>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Internal buffer size (in bytes) currently held for an in-progress
    /// frame. Exposed for tests: a fatal prefix must be rejected *before*
    /// its body is buffered.
    pub fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Buffer `bytes` and decode as many complete frames as possible.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let mut input = bytes;
        loop {
            match self.need {
                None => {
                    // Reading the 4-byte big-endian prefix; partial prefix
                    // bytes from earlier feeds are kept in `buf`.
                    let take = input.len().min(4 - self.buf.len());
                    self.buf.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    if self.buf.len() < 4 {
                        return Ok(());
                    }
                    let declared = u32::from_be_bytes(self.buf[..4].try_into().unwrap());
                    self.buf.clear(); // prefix bytes were not payload
                    if declared > MAX_FRAME_BYTES {
                        // Reject immediately, before buffering the body.
                        return Err(WireError::FrameTooLarge {
                            declared,
                            max: MAX_FRAME_BYTES,
                        });
                    }
                    if declared == 0 {
                        return Err(WireError::ZeroLengthFrame);
                    }
                    self.need = Some(declared as usize);
                }
                Some(need) => {
                    if self.buf.len() >= need {
                        // Frame complete.
                        self.completed
                            .push_back(self.buf.split_off(0));
                        self.need = None;
                        continue;
                    }
                    let take = input.len().min(need - self.buf.len());
                    self.buf.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    if take == 0 {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Pop one complete frame payload, if a full frame is buffered.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        Ok(self.completed.pop_front())
    }
}

/// Serialize `msg` to JSON and frame it (u32 BE length + payload),
/// appending to `out` (spec §2 `encode`).
pub fn encode(
    msg: &impl serde::Serialize,
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    let payload =
        serde_json::to_vec(msg).map_err(|e| WireError::Json(e.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES as usize {
        return Err(WireError::FrameTooLarge {
            declared: payload.len().min(u32::MAX as usize) as u32,
            max: MAX_FRAME_BYTES,
        });
    }
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn len_prefix(n: u32) -> [u8; 4] {
        n.to_be_bytes()
    }

    #[test]
    fn single_frame() {
        let mut d = Decoder::new();
        d.feed(&len_prefix(3)).unwrap();
        assert_eq!(d.next_frame(), Ok(None));
        d.feed(b"abc").unwrap();
        assert_eq!(d.next_frame(), Ok(Some(b"abc".to_vec())));
        assert_eq!(d.next_frame(), Ok(None));
    }

    #[test]
    fn multiple_frames_in_one_feed() {
        let mut d = Decoder::new();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&len_prefix(2));
        bytes.extend_from_slice(b"ab");
        bytes.extend_from_slice(&len_prefix(1));
        bytes.extend_from_slice(b"c");
        d.feed(&bytes).unwrap();
        assert_eq!(d.next_frame(), Ok(Some(b"ab".to_vec())));
        assert_eq!(d.next_frame(), Ok(Some(b"c".to_vec())));
        assert_eq!(d.next_frame(), Ok(None));
    }

    #[test]
    fn byte_at_a_time() {
        let mut d = Decoder::new();
        // u32 BE prefix for length 5: 0x00 0x00 0x00 0x05
        let frame = [0u8, 0, 0, 5, b'x', b'y', b'z', b'w', b'v'];
        for b in frame {
            d.feed(&[b]).unwrap();
        }
        assert_eq!(d.next_frame(), Ok(Some(b"xyzwv".to_vec())));
    }

    #[test]
    fn oversized_prefix_rejected_without_buffering_body() {
        let mut d = Decoder::new();
        let mut bytes = len_prefix(MAX_FRAME_BYTES + 1).to_vec();
        bytes.extend_from_slice(&[0u8; 1024]); // pretend body already arrived
        let err = d.feed(&bytes).unwrap_err();
        assert_eq!(
            err,
            WireError::FrameTooLarge {
                declared: MAX_FRAME_BYTES + 1,
                max: MAX_FRAME_BYTES,
            }
        );
        // The body must not have been buffered (spec §6: "reject without
        // buffering the body").
        assert_eq!(d.buffered_bytes(), 0);
    }

    #[test]
    fn zero_length_prefix_rejected() {
        let mut d = Decoder::new();
        assert_eq!(
            d.feed(&len_prefix(0)).unwrap_err(),
            WireError::ZeroLengthFrame
        );
    }

    #[test]
    fn max_size_frame_accepted() {
        // Exactly MAX_FRAME_BYTES is legal (only *exceeding* is a violation).
        let mut d = Decoder::new();
        d.feed(&len_prefix(MAX_FRAME_BYTES)).unwrap();
        assert_eq!(d.next_frame(), Ok(None));
        // Feed the body in chunks to avoid a 1 MiB allocation in tests.
        let chunk = vec![b'a'; 65_536];
        for _ in 0..(MAX_FRAME_BYTES as usize / 65_536) {
            d.feed(&chunk).unwrap();
        }
        let frame = d.next_frame().unwrap().unwrap();
        assert_eq!(frame.len(), MAX_FRAME_BYTES as usize);
    }
}
