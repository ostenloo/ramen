//! Codec edge cases (`01-protocol.md` M1 acceptance).
//!
//! - Arbitrary chunk boundaries, including the specified prefix splits
//!   (1/3, 2/2, 3/1).
//! - Oversize prefixes rejected before any body is buffered.
//! - Zero-length frames rejected.
//! - Invalid UTF-8 / invalid JSON payloads rejected with the right
//!   `ProtoError`/`CodecError` variant.

use ramen_proto::{CodecError, Decoder, Message, PROTOCOL_VERSION, MAX_FRAME_BYTES};

fn framed(payload: &str) -> Vec<u8> {
    let mut out = Vec::new();
    ramen_proto::encode(&payload.to_string(), &mut out).unwrap();
    out
}

/// Split `frame` so the 4-byte prefix is divided `a` bytes then `b` bytes
/// (a + b == 4), and the body is delivered in a single feed after.
fn feed_prefix_split(d: &mut Decoder, frame: &[u8], a: usize) {
    d.feed(&frame[..a]).unwrap();
    d.feed(&frame[a..4]).unwrap();
    d.feed(&frame[4..]).unwrap();
}

#[test]
fn prefix_split_1_of_3() {
    let f = framed("{\"v\":1}");
    let mut d = Decoder::new();
    feed_prefix_split(&mut d, &f, 1);
    let got = d.next_frame().unwrap().unwrap();
    assert_eq!(got, f[4..]);
    assert!(d.next_frame().unwrap().is_none());
}

#[test]
fn prefix_split_2_of_2() {
    let f = framed("{\"v\":1}");
    let mut d = Decoder::new();
    feed_prefix_split(&mut d, &f, 2);
    assert_eq!(d.next_frame().unwrap().unwrap(), f[4..]);
}

#[test]
fn prefix_split_3_of_1() {
    let f = framed("{\"v\":1}");
    let mut d = Decoder::new();
    feed_prefix_split(&mut d, &f, 3);
    assert_eq!(d.next_frame().unwrap().unwrap(), f[4..]);
}

#[test]
fn body_split_arbitrarily() {
    let f = framed("01234567890123456789");
    let mut d = Decoder::new();
    // Feed one byte at a time across the whole frame.
    for b in &f {
        d.feed(std::slice::from_ref(b)).unwrap();
    }
    assert_eq!(d.next_frame().unwrap().unwrap(), f[4..]);
}

#[test]
fn body_split_every_byte_boundary() {
    let f = framed("hello, world");
    for split in 1..f.len() {
        let mut d = Decoder::new();
        d.feed(&f[..split]).unwrap();
        d.feed(&f[split..]).unwrap();
        assert_eq!(d.next_frame().unwrap().unwrap(), f[4..]);
    }
}

#[test]
fn two_frames_one_feed_one_frame_one_feed() {
    let f1 = framed("aaaa");
    let f2 = framed("bb");
    let mut d = Decoder::new();
    d.feed(&f1).unwrap();
    assert_eq!(d.next_frame().unwrap().unwrap(), f1[4..]);
    d.feed(&f2).unwrap();
    assert_eq!(d.next_frame().unwrap().unwrap(), f2[4..]);
}

#[test]
fn oversize_prefix_buffers_no_body() {
    let mut d = Decoder::new();
    let mut stream = (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
    stream.extend_from_slice(&[b'J'; 50]); // would-be body
    let err = d.feed(&stream).unwrap_err();
    let max_plus_1 = MAX_FRAME_BYTES + 1;
    assert!(
        matches!(err, CodecError::FrameTooLarge { declared: d, max: m } if d == max_plus_1 && m == MAX_FRAME_BYTES),
        "unexpected error: {err:?}"
    );
    // The 50 body bytes must NOT be in the decoder.
    assert_eq!(d.buffered_len(), 0);
}

#[test]
fn oversize_prefix_declared_exactly_at_limit_is_fine() {
    // Exactly MAX_FRAME_BYTES is allowed (the limit is inclusive).
    // A JSON array of digits is exactly MAX bytes; feed it in one go.
    let body: String = format!("[{}]", "1".repeat(MAX_FRAME_BYTES as usize - 2));
    let mut f = (body.len() as u32).to_be_bytes().to_vec();
    f.extend(body.bytes());
    let mut d = Decoder::new();
    d.feed(&f).unwrap();
    let got = d.next_frame().unwrap().unwrap();
    assert_eq!(got.len(), MAX_FRAME_BYTES as usize);
}

#[test]
fn zero_length_frame_rejected() {
    let mut d = Decoder::new();
    let err = d.feed(&[0, 0, 0, 0]).unwrap_err();
    assert!(matches!(err, CodecError::ZeroLengthFrame));
}

#[test]
fn invalid_utf8_payload_rejected_at_decode() {
    let mut f = Vec::new();
    let body: Vec<u8> = vec![0xff, 0xfe, 0xfd]; // not UTF-8
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(&body);
    let err = Message::decode(&f[4..]).unwrap_err();
    assert!(matches!(err, ramen_proto::ProtoError::Codec(CodecError::Utf8(_))));
}

#[test]
fn invalid_json_payload_rejected_at_decode() {
    let f = framed("{not json");
    let err = Message::decode(&f[4..]).unwrap_err();
    assert!(matches!(err, ramen_proto::ProtoError::Codec(CodecError::Json(_))));
}

#[test]
fn encode_rejects_oversize_payload() {
    // A string of MAX-1 chars serializes to exactly MAX+1 bytes (two quotes),
    // one over the limit.
    let big = "x".repeat(MAX_FRAME_BYTES as usize - 1);
    let mut out = Vec::new();
    let err = ramen_proto::encode(&big, &mut out).unwrap_err();
    let max_plus_1 = MAX_FRAME_BYTES + 1;
    assert!(matches!(
        err,
        CodecError::FrameTooLarge { declared: d, max: m } if d == max_plus_1 && m == MAX_FRAME_BYTES
    ));
}

#[test]
fn frame_length_prefix_is_big_endian() {
    let f = framed("abcd"); // serializes to the 6-byte JSON string `"abcd"`
    assert_eq!(f[..4], [0, 0, 0, 6]);
    assert_eq!(&f[4..], b"\"abcd\"");
}

#[test]
fn version_constant_matches_envelopes() {
    // Every constructor stamps PROTOCOL_VERSION; decode + ensure_version must
    // accept it.
    let msg = Message::Fault(ramen_proto::Fault::new(
        ramen_proto::ErrorCode::Internal,
        "t",
    ));
    assert_eq!(msg.version(), PROTOCOL_VERSION);
    msg.ensure_version().unwrap();
}
