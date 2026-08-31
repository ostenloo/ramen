//! `ramen-sdk`: the Ramen client library.
//!
//! This crate is an **independent implementation** of the wire protocol
//! defined by `01-protocol.md`. It shares no code with `ramen-proto`;
//! the two are reconciled only by the golden-fixture round-trip tests
//! (`tests/golden.rs`). This independence is deliberate (spec
//! 06-ramenctl.md §1): the SDK is the instrument that proves the spec is
//! self-sufficient.
//!
//! # Transport scope
//!
//! `SdkError` covers transport, framing, and handshake failures only.
//! Denials and protocol-level `Error` responses are *outcomes* of a
//! successful round-trip and surface in [`OpOutcome`].

mod wire;

pub use wire::codec::{encode, Decoder, WireError, MAX_FRAME_BYTES};
pub use wire::{
    CapabilitySummary, ClientInfo, Constraints, DenialCode, ErrorCode, Fault,
    FileWriteOp, Hello, Message, Operation, Reversibility, Request, RequestId,
    Response, SessionId, WhoamiOp, WriteMode, PROTOCOL_VERSION,
};

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use biscuit_auth::UnverifiedBiscuit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

/// Errors for transport, framing, and handshake failures only (spec §8:
/// these are the SDK's `SdkError`).
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("transport: {0}")]
    Transport(#[source] std::io::Error),
    #[error("framing: {0}")]
    Framing(#[from] WireError),
    #[error("token could not be serialized: {0}")]
    Token(String),
    /// Supervisor answered the handshake with a terminal `Error` envelope.
    #[error("handshake rejected: {code:?}: {message}")]
    Handshake { code: ErrorCode, message: String },
    /// The connection closed before a `Welcome` arrived.
    #[error("connection closed before handshake")]
    HandshakeClosed,
    /// EOF or peer failure while an operation was in flight (or at send).
    #[error("connection closed")]
    ConnectionClosed,
    /// The supervisor sent a message that is not legal at this point.
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),
    /// The supervisor sent a best-effort `Fault` and closed the connection.
    #[error("fault from supervisor: {code:?}: {message}")]
    Fault { code: ErrorCode, message: String },
}

/// Terminal outcome of an operation (spec 06-ramenctl.md §2).
///
/// `Ok` carries the op-specific result as JSON. `Error` (added by the M7
/// spec amendment — see the M7 commit) carries a protocol-level machinery
/// failure from the supervisor; it is an outcome, not an SDK error, because
/// the round-trip itself succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpOutcome {
    Ok(serde_json::Value),
    Denied {
        code: DenialCode,
        reason: String,
        audit_seq: u64,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

struct InFlight {
    tx: oneshot::Sender<Result<OpOutcome, SdkError>>,
}

/// A connected, authenticated Ramen client (spec 06-ramenctl.md §2).
///
/// One `Client` serves concurrent calls: requests are serialized on a
/// single writer task and responses are matched to callers by request ID on
/// the reader task. `Client` is `Send + Sync`; `call` takes `&self`.
pub struct Client {
    session: SessionId,
    identity: String,
    out: mpsc::Sender<Vec<u8>>,
    pending: Arc<Mutex<HashMap<RequestId, InFlight>>>,
}

impl Client {
    /// Connect to the supervisor socket, send `Hello`, and wait for
    /// `Welcome`.
    ///
    /// The token is passed as an `UnverifiedBiscuit` (M7 amendment to the
    /// spec's `&Biscuit`): a client cannot hold a *verified* biscuit, since
    /// verification requires the root public key, which only the supervisor
    /// and the minter hold (04-guard.md §3).
    pub async fn connect(
        socket: &Path,
        token: &UnverifiedBiscuit,
    ) -> Result<Self, SdkError> {
        let token_b64 = token
            .to_base64()
            .map_err(|e| SdkError::Token(e.to_string()))?;

        let client_info = ClientInfo::new("ramen-sdk", env!("CARGO_PKG_VERSION"));

        let stream =
            UnixStream::connect(socket).await.map_err(SdkError::Transport)?;
        let (read, write) = stream.into_split();

        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            let mut w = write;
            while let Some(frame) = out_rx.recv().await {
                if w.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });

        // Handshake: Hello, then wait for Welcome.
        let hello = Message::Hello(Hello::new(token_b64, client_info));
        let mut frame = Vec::new();
        encode(&hello, &mut frame).map_err(SdkError::Framing)?;
        out_tx
            .send(frame)
            .await
            .map_err(|_| SdkError::ConnectionClosed)?;

        let mut dec = Decoder::new();
        let mut buf = vec![0u8; 8192];
        let mut rd = read;
        let welcome = loop {
            match rd.read(&mut buf).await {
                Ok(0) => return Err(SdkError::HandshakeClosed),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SdkError::Transport(e)),
                Ok(n) => {
                    dec.feed(&buf[..n]).map_err(SdkError::Framing)?;
                    if let Some(f) = dec.next_frame().map_err(SdkError::Framing)? {
                        let msg = parse_received(&f).map_err(|e| e.into_sdk_error())?;
                        match msg {
                            Message::Welcome(w) => break w,
                            Message::Response(Response::Error { error, .. }) => {
                                return Err(SdkError::Handshake {
                                    code: error.code,
                                    message: error.message,
                                });
                            }
                            other => {
                                return Err(SdkError::ProtocolViolation(
                                    format!("expected Welcome first, got {other:?}"),
                                ));
                            }
                        }
                    }
                }
            }
        };

        let pending = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(reader_task(rd, pending.clone()));

        Ok(Self {
            session: welcome.session,
            identity: welcome.identity,
            out: out_tx,
            pending,
        })
    }

    /// Session ID from the `Welcome`.
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// Identity derived from the token claims (same in `Welcome` and in the
    /// live `Whoami` result).
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Issue an operation and await its terminal outcome.
    ///
    /// v0 has exactly three terminal statuses; the round-trip resolves when
    /// the supervisor's terminal response for this request ID arrives
    /// (responses are matched by ID, never by order).
    pub async fn call(&self, op: Operation) -> Result<OpOutcome, SdkError> {
        let id = RequestId::new();
        let req = Message::Request(Request::new(id, op));
        let mut frame = Vec::new();
        encode(&req, &mut frame).map_err(SdkError::Framing)?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(
            id,
            InFlight {
                tx,
            },
        );

        if self.out.send(frame).await.is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(SdkError::ConnectionClosed);
        }

        match rx.await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(SdkError::ConnectionClosed),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Dropping the sender ends the writer task, which drops the write
        // half; the supervisor sees EOF and the reader fails any pending
        // calls with ConnectionClosed.
    }
}

/// A frame the supervisor sent that the client cannot accept: either illegal
/// framing (`Framing`) or a well-formed envelope whose `v` differs from the
/// client's `PROTOCOL_VERSION` (`VersionMismatch`). Cloneable so a single
/// error can be handed to every in-flight call.
#[derive(Clone, Debug)]
enum ReceivedError {
    Framing(WireError),
    VersionMismatch(u16),
}

impl ReceivedError {
    fn into_sdk_error(self) -> SdkError {
        match self {
            ReceivedError::Framing(e) => SdkError::Framing(e),
            // A version mismatch is a transport error (spec §4): the client
            // closes the connection and fails every in-flight call.
            ReceivedError::VersionMismatch(v) => SdkError::ProtocolViolation(format!(
                "version mismatch: got {v}, expected {PROTOCOL_VERSION}"
            )),
        }
    }
}

/// Parse a frame received from the supervisor and validate its `v`
/// (`01-protocol.md` §4: the version is validated before the body is parsed,
/// so a frame from another protocol version never reaches the body dispatch).
///
/// `v` is read with a shallow scan that never inspects past the version
/// field: the ordering guarantee is only as strong as the shallowest thing
/// that can fail first, so a frame from another protocol version — even one
/// whose body already uses a future encoding — must surface as a version
/// error, not a framing error. If `v` cannot be read as a clean non-negative
/// integer at the top level, the full parse runs and the real framing error
/// surfaces.
fn parse_received(frame: &[u8]) -> Result<Message, ReceivedError> {
    if let Some(v) = shallow_version(frame) {
        if v != PROTOCOL_VERSION {
            return Err(ReceivedError::VersionMismatch(v));
        }
    }
    let msg = Message::from_bytes(frame).map_err(ReceivedError::Framing)?;
    Ok(msg)
}

/// Read the top-level `v` field of a JSON object without parsing the rest of
/// the frame. Returns `None` when the frame does not begin with a top-level
/// object carrying a clean integer `v`; that is not an error on its own —
/// the full parse is what reports it.
fn shallow_version(frame: &[u8]) -> Option<u16> {
    const WS: &[u8] = b" \t\n\r";
    let mut i = 0usize;
    let skip_ws = |i: &mut usize| {
        while *i < frame.len() && WS.contains(&frame[*i]) {
            *i += 1;
        }
    };

    skip_ws(&mut i);
    if frame.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;

    loop {
        skip_ws(&mut i);
        match frame.get(i) {
            None => return None,
            Some(&b'}') => return None, // top-level object ended without `v`
            Some(&b',') => {
                i += 1;
                continue;
            }
            Some(&b'"') => {}
            _ => return None, // not an object key
        }
        // Key string: `i` is at the opening quote; scan to the close.
        i += 1;
        let kstart = i;
        loop {
            match frame.get(i) {
                None => return None,
                Some(&b'\\') => i += 2,
                Some(&b'"') => break,
                Some(_) => i += 1,
            }
        }
        let key = &frame[kstart..i];
        i += 1; // closing quote
        skip_ws(&mut i);
        if frame.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        skip_ws(&mut i);

        if key == b"v" {
            let dstart = i;
            let mut v: u64 = 0;
            while let Some(&d) = frame.get(i) {
                if !d.is_ascii_digit() {
                    break;
                }
                v = v.checked_mul(10)?.checked_add((d - b'0') as u64)?;
                i += 1;
            }
            // No digits at all (e.g. `"v":"1"`): the full parse reports the
            // type error; a `Some(0)` here would surface as a bogus version
            // mismatch.
            if i == dstart {
                return None;
            }
            // `1.5`, `1e3`, `1x`: not a clean integer literal — let the full
            // parse report it.
            if matches!(frame.get(i), Some(&c) if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E') {
                return None;
            }
            return u16::try_from(v).ok();
        }

        // Another key: skip its value, then expect `,` or `}`.
        if !skip_json_value(frame, &mut i) {
            return None;
        }
        skip_ws(&mut i);
        if !matches!(frame.get(i), Some(&b',') | Some(&b'}')) {
            return None;
        }
        if frame[i] == b'}' {
            return None;
        }
        i += 1;
    }
}

/// Skip one JSON value starting at `i`, advancing `i` past it. Shallow by
/// design: it only needs to be *right* on values that precede `v` in a
/// frame the full parser would accept; everything else falls through to the
/// full parse, which reports the real error.
fn skip_json_value(frame: &[u8], i: &mut usize) -> bool {
    const WS: &[u8] = b" \t\n\r";
    while *i < frame.len() && WS.contains(&frame[*i]) {
        *i += 1;
    }
    match frame.get(*i) {
        Some(&b'"') => {
            *i += 1;
            loop {
                match frame.get(*i) {
                    None => return false,
                    Some(&b'\\') => *i += 2,
                    Some(&b'"') => {
                        *i += 1;
                        return true;
                    }
                    Some(_) => *i += 1,
                }
            }
        }
        Some(&b'{') | Some(&b'[') => {
            let mut depth = 0usize;
            let mut in_str = false;
            while *i < frame.len() {
                match frame[*i] {
                    b'\\' if in_str => *i += 2,
                    b'"' => {
                        in_str = !in_str;
                        *i += 1;
                    }
                    b'{' | b'[' if !in_str => {
                        depth += 1;
                        *i += 1;
                    }
                    b'}' | b']' if !in_str => {
                        depth -= 1;
                        *i += 1;
                        if depth == 0 {
                            return true;
                        }
                    }
                    _ => *i += 1,
                }
            }
            false
        }
        Some(&c) if c.is_ascii_digit() || c == b'-' => {
            *i += 1;
            while let Some(&c) = frame.get(*i) {
                if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'+' {
                    *i += 1;
                } else {
                    break;
                }
            }
            true
        }
        Some(_) => {
            // true / false / null: skip to the next structural character.
            let start = *i;
            while *i < frame.len() && !b",}]\n\t ".contains(&frame[*i]) {
                *i += 1;
            }
            *i > start
        }
        None => false,
    }
}

/// Fail every in-flight call (used on EOF, framing death, and `Fault`).
fn fail_all(
    pending: &Arc<Mutex<HashMap<RequestId, InFlight>>>,
    make_err: impl Fn() -> SdkError,
) {
    for (_, in_flight) in pending.lock().unwrap().drain() {
        let _ = in_flight.tx.send(Err(make_err()));
    }
}

async fn reader_task(
    mut rd: OwnedReadHalf,
    pending: Arc<Mutex<HashMap<RequestId, InFlight>>>,
) {
    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 8192];
    let mut dead = false;
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
            Ok(n) => {
                if let Err(e) = dec.feed(&buf[..n]) {
                    fail_all(&pending, || SdkError::Framing(e.clone()));
                    dead = true;
                    break;
                }
                'frames: while let Some(frame) = dec.next_frame().unwrap() {
                    match parse_received(&frame) {
                        Err(e) => {
                            fail_all(&pending, || e.clone().into_sdk_error());
                            dead = true;
                            break 'frames;
                        }
                        Ok(Message::Response(r)) => handle_response(&pending, r),
                        Ok(Message::Fault(f)) => {
                            fail_all(
                                &pending,
                                || SdkError::Fault {
                                    code: f.error.code,
                                    message: f.error.message.clone(),
                                },
                            );
                            dead = true;
                            break 'frames;
                        }
                        Ok(other) => {
                            fail_all(
                                &pending,
                                || SdkError::ProtocolViolation(format!(
                                    "unexpected message after handshake: {other:?}"
                                )),
                            );
                            dead = true;
                            break 'frames;
                        }
                    }
                }
            }
        }
    }
    if !dead {
        fail_all(&pending, || SdkError::ConnectionClosed);
    }
}

fn handle_response(
    pending: &Arc<Mutex<HashMap<RequestId, InFlight>>>,
    r: Response,
) {
    match r {
        Response::Ok { id, result, .. } => resolve(pending, id, OpOutcome::Ok(result)),
        Response::Denied { id, denial, .. } => resolve(
            pending,
            id,
            OpOutcome::Denied {
                code: denial.code,
                reason: denial.reason,
                audit_seq: denial.audit_seq,
            },
        ),
        Response::Error { id, error, .. } => resolve(
            pending,
            id,
            OpOutcome::Error {
                code: error.code,
                message: error.message,
            },
        ),
    }
}

fn resolve(
    pending: &Arc<Mutex<HashMap<RequestId, InFlight>>>,
    id: RequestId,
    outcome: OpOutcome,
) {
    if let Some(in_flight) = pending.lock().unwrap().remove(&id) {
        let _ = in_flight.tx.send(Ok(outcome));
    }
    // An unknown ID is protocol-illegal from the supervisor; ignore
    // defensively rather than tear down the connection.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame from a different protocol version must be rejected *before*
    /// body dispatch, in exactly the same shape as a framing error (spec §4:
    /// the version is validated before the body is parsed). Without the check,
    /// a `v: 2` response would be parsed and matched to an in-flight call.
    #[test]
    fn parse_received_rejects_wrong_version_on_every_envelope() {
        // The closed-set decision makes this load-bearing: a `v: 2` supervisor
        // may add denial/error codes this client does not know, so the client
        // must refuse the frame on version alone, never on the body.
        let welcome = r#"{"v":2,"type":"Welcome","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","identity":"i","capabilities":[]}"#;
        let resp = r#"{"v":2,"status":"Ok","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","result":{"identity":"agent:planner","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","capabilities":[],"token_expires_at":null}}"#;
        // A v2 body with a field this client's closed set does not know: the
        // version check must win over body validation, or this frame would
        // surface as a framing error instead of a version error (spec §4).
        let resp_v2_body = r#"{"v":2,"status":"Ok","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","result":{"identity":"agent:planner","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","capabilities":[],"token_expires_at":null,"extra":1}}"#;
        // A v2 body that is not valid JSON past the version field (a future
        // encoding): the version check must still win — the ordering
        // guarantee is only as strong as the shallowest thing that can fail
        // first.
        let resp_v2_future_encoding = r#"{"v":2,"status":"Ok","result":{not json"#;
        // `v` as the last field: the shallow scan must skip the earlier
        // values to reach it.
        let resp_v2_last = r#"{"status":"Ok","id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","v":2}"#;
        let fault = r#"{"v":2,"type":"Fault","error":{"code":"Internal","message":"x"}}"#;
        for payload in [welcome, resp, resp_v2_body, resp_v2_future_encoding, resp_v2_last, fault] {
            let e = parse_received(payload.as_bytes()).unwrap_err();
            assert!(
                matches!(e, ReceivedError::VersionMismatch(2)),
                "expected VersionMismatch(2) for {payload}, got {e:?}"
            );
            let sdk_err = e.clone().into_sdk_error();
            match sdk_err {
                SdkError::ProtocolViolation(msg) => {
                    assert!(msg.contains("version mismatch"), "got: {msg}");
                    assert!(msg.contains("2"), "got: {msg}");
                }
                other => panic!("expected ProtocolViolation, got {other:?}"),
            }
        }
    }

    #[test]
    fn shallow_version_reads_only_as_much_as_the_version() {
        // The version, wherever it sits at the top level.
        assert_eq!(shallow_version(b"{\"v\":1}"), Some(1));
        assert_eq!(shallow_version(b"{\"status\":\"Ok\",\"v\":1}"), Some(1));
        assert_eq!(
            shallow_version(b"{\"v\": 2 ,\"junk\":{\"a\":[1,{\"b\":\"x\"}]}}"),
            Some(2)
        );
        // Not a top-level object, or no clean integer `v`: the full parse
        // reports these, the shallow scan must not get an answer.
        assert_eq!(shallow_version(b"[1]"), None);
        assert_eq!(shallow_version(b"{\"status\":\"Ok\"}"), None);
        assert_eq!(shallow_version(b"{\"v\":\"1\"}"), None);
        assert_eq!(shallow_version(b"{\"v\":1.5}"), None);
        assert_eq!(shallow_version(b"{\"v\":65536}"), None);
        assert_eq!(shallow_version(b"{}garbage"), None);
    }

    #[test]
    fn parse_received_accepts_matching_version() {
        let welcome = r#"{"v":1,"type":"Welcome","session":"01ARZ3NDEKTSV4RRFFQ69G5FAV","identity":"i","capabilities":[]}"#;
        assert!(matches!(
            parse_received(welcome.as_bytes()).unwrap(),
            Message::Welcome(_)
        ));
    }

    #[test]
    fn parse_received_still_reports_framing_errors() {
        // Malformed JSON is a framing error, not a version error.
        let e = parse_received(b"{not json").unwrap_err();
        assert!(matches!(e, ReceivedError::Framing(_)));
        // Duplicate keys remain rejected (protocol's asserted behavior).
        let e = parse_received(b"{\"v\":1,\"v\":2}").unwrap_err();
        assert!(matches!(e, ReceivedError::Framing(_)));
    }
}
