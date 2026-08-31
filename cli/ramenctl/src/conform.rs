//! `ramenctl conform` — the protocol conformance harness
//! (`06-ramenctl.md` §4).
//!
//! Sends deliberately wrong things to a **raw** Unix socket, bypassing
//! `ramen-sdk`: through the SDK it could only send things the SDK can
//! express, which is precisely the set of things that are already
//! well-formed.
//!
//! Each check opens a fresh connection, sends its stimulus, and asserts the
//! expected outcome. "Close" checks accept a best-effort `Fault` frame
//! before the close (`01-protocol.md` §8: the supervisor "attempts to send a
//! final `Fault` on a best-effort basis and closes the connection").
//!
//! Exits 0 when every check passes, 2 (protocol error) otherwise.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine;
use ramen_sdk::MAX_FRAME_BYTES;
use serde_json::json;

const TIMEOUT: Duration = Duration::from_secs(5);

const CLIENT_NAME: &str = "ramenctl";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

struct Check {
    name: &'static str,
    pass: bool,
    detail: String,
}

fn check(name: &'static str, pass: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        pass,
        detail: detail.into(),
    }
}

pub fn run(
    socket: &Path,
    token_file: &Path,
    prefix: &Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let token = match std::fs::read_to_string(token_file) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            return fail_all(
                vec![check(
                    "setup",
                    false,
                    format!("cannot read token file: {e}"),
                )],
                as_json,
            )
        }
    };

    // Canonicalize for the FileWrite variance: the supervisor reports the
    // canonical target path in the result (macOS /var → /private/var).
    let prefix = prefix
        .as_ref()
        .and_then(|p| std::fs::canonicalize(p).ok());

    let checks = vec![
        frame_oversize(socket),
        frame_zero(socket),
        frame_split(socket, &token),
        bad_utf8(socket),
        bad_json(socket),
        version_mismatch(socket, &token),
        no_hello(socket),
        double_hello(socket, &token),
        unknown_field(socket, &token),
        dup_request_id(socket, &token),
        unknown_op(socket, &token),
        concurrent(socket, &token),
        out_of_order(socket, &token, prefix.as_deref()),
    ];

    fail_all(checks, as_json)
}

fn fail_all(checks: Vec<Check>, as_json: bool) -> ExitCode {
    let n_pass = checks.iter().filter(|c| c.pass).count();
    let n_total = checks.len();
    if as_json {
        let arr: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| json!({ "check": c.name, "pass": c.pass, "detail": c.detail }))
            .collect();
        println!(
            "{}",
            json!({ "passed": n_pass, "total": n_total, "checks": arr })
        );
    } else {
        for c in &checks {
            println!(
                "  {:<18} {:<4} {}",
                c.name,
                if c.pass { "PASS" } else { "FAIL" },
                c.detail
            );
        }
        println!("conform: {n_pass}/{n_total} checks passed");
    }
    if n_pass == n_total {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

// ---------------------------------------------------------------------------
// Raw framing
// ---------------------------------------------------------------------------

/// A raw connection with read/write timeouts so a hung supervisor fails the
/// check instead of hanging CI.
struct Raw {
    s: UnixStream,
}

impl Raw {
    fn connect(socket: &Path) -> std::io::Result<Self> {
        let s = UnixStream::connect(socket)?;
        s.set_read_timeout(Some(TIMEOUT))?;
        s.set_write_timeout(Some(TIMEOUT))?;
        Ok(Self { s })
    }

    fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.s.write_all(bytes)
    }

    /// Read exactly `buf.len()` bytes. `Ok(None)`: complete. `Ok(n)`: EOF
    /// after `n` bytes. `Err`: RST/timeout.
    fn read_exact_n(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        let mut got = 0;
        while got < buf.len() {
            match self.s.read(&mut buf[got..]) {
                Ok(0) => return Ok(Some(got)),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// One frame: 4-byte BE length + JSON body. `Ok(None)` = clean EOF.
    fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut len = [0u8; 4];
        if let Some(got) = self.read_exact_n(&mut len)? {
            if got == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated length prefix",
            ));
        }
        let n = u32::from_be_bytes(len);
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zero-length frame",
            ));
        }
        if n > MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame over MAX_FRAME_BYTES",
            ));
        }
        let mut body = vec![0u8; n as usize];
        if self.read_exact_n(&mut body)?.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated frame body",
            ));
        }
        Ok(Some(body))
    }

    /// Read frames until the connection closes. Returns the frames (a
    /// best-effort `Fault` included) and a description of the close.
    fn drain_to_close(&mut self) -> (Vec<Vec<u8>>, String) {
        let mut frames = Vec::new();
        loop {
            match self.read_frame() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => return (frames, "closed".to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return (frames, "closed (RST)".to_string())
                }
                Err(e) => return (frames, format!("read error: {e}")),
            }
        }
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn hello(token: &str) -> Vec<u8> {
    frame(
        json!({
            "v": 1,
            "type": "Hello",
            "token": token,
            "client": { "name": CLIENT_NAME, "version": CLIENT_VERSION },
        })
        .to_string()
        .as_bytes(),
    )
}

fn whoami_request(id: &str) -> Vec<u8> {
    frame(
        json!({ "v": 1, "id": id, "op": { "type": "Whoami" } })
            .to_string()
            .as_bytes(),
    )
}

fn filewrite_request(id: &str, path: &str, content_b64: &str) -> Vec<u8> {
    frame(
        json!({
            "v": 1,
            "id": id,
            "op": {
                "type": "FileWrite",
                "path": path,
                "content_b64": content_b64,
                "mode": "Create",
            },
        })
        .to_string()
        .as_bytes(),
    )
}

/// A valid but distinct ULID (Crockford base32, 26 chars; digits and A–H are
/// all in the alphabet).
fn req_id(i: u8) -> String {
    let alphabet = b"0123456789ABCDEFGH";
    let c = alphabet[i as usize] as char;
    format!("{}{c}", "0".repeat(25))
}

fn eof() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "connection closed")
}

/// Connect; on failure, fail the check with the connect error.
fn connect_or_fail(name: &'static str, socket: &Path) -> Result<Raw, Check> {
    match Raw::connect(socket) {
        Ok(r) => Ok(r),
        Err(e) => Err(check(name, false, format!("connect failed: {e}"))),
    }
}

/// Assert the connection closed (clean EOF or RST). A best-effort `Fault`
/// frame before the close is acceptable (spec §8).
fn closed_pass(name: &'static str, frames: &[Vec<u8>], close: &str) -> Check {
    let ok = matches!(close, "closed" | "closed (RST)");
    let mut detail = close.to_string();
    if let Some(f) = frames.first() {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(f) {
            if v.get("type").and_then(|t| t.as_str()) == Some("Fault") {
                detail = format!(
                    "{close} (after Fault/{})",
                    v["error"]["code"]
                );
            }
        }
    }
    check(name, ok, detail)
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// `frame_oversize`: prefix of `MAX_FRAME_BYTES + 1`. The supervisor must
/// close without reading a body — we never send one, so "closed promptly"
/// is the assertion (a body-reading supervisor would time us out).
fn frame_oversize(socket: &Path) -> Check {
    let name = "frame_oversize";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let _ = raw.send(&((MAX_FRAME_BYTES + 1).to_be_bytes()));
    let (frames, close) = raw.drain_to_close();
    if !matches!(close.as_str(), "closed" | "closed (RST)") {
        return check(
            name,
            false,
            format!("{close} — expected close without reading body"),
        );
    }
    closed_pass(name, &frames, &close)
}

/// `frame_zero`: prefix of 0 → close.
fn frame_zero(socket: &Path) -> Check {
    let name = "frame_zero";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let _ = raw.send(&0u32.to_be_bytes());
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `frame_split`: a valid request, 1 byte per write → normal response.
fn frame_split(socket: &Path, token: &str) -> Check {
    let name = "frame_split";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let h = hello(token);
    for b in &h {
        if raw.send(std::slice::from_ref(b)).is_err() {
            return check(name, false, "write failed while splitting hello");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    match handshake_response(&mut raw) {
        Ok(()) => {}
        Err(d) => return check(name, false, format!("{d}")),
    }
    let req = whoami_request(&req_id(0));
    for b in &req {
        if raw.send(std::slice::from_ref(b)).is_err() {
            return check(name, false, "write failed while splitting request");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    match raw.read_frame() {
        Ok(Some(f)) => {
            let v: serde_json::Value = match serde_json::from_slice(&f) {
                Ok(v) => v,
                Err(e) => return check(name, false, format!("bad response: {e}")),
            };
            if v["status"] == "Ok" {
                check(name, true, "welcome + ok response, 1 byte per write")
            } else {
                check(name, false, format!("expected status Ok, got: {v}"))
            }
        }
        Ok(None) => check(name, false, "connection closed before response"),
        Err(e) => check(name, false, format!("read error: {e}")),
    }
}

/// Read the `Welcome` after a (possibly split) hello.
fn handshake_response(raw: &mut Raw) -> std::io::Result<()> {
    let f = raw.read_frame()?.ok_or_else(eof)?;
    let v: serde_json::Value = serde_json::from_slice(&f).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    if v["type"] != "Welcome" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected Welcome, got: {f:?}"),
        ));
    }
    Ok(())
}

/// `bad_utf8`: prefix + invalid UTF-8 → close.
fn bad_utf8(socket: &Path) -> Check {
    let name = "bad_utf8";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let payload = [0xFFu8, 0xFF, 0xFF, 0xFF];
    let _ = raw.send(&frame(&payload));
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `bad_json`: prefix + `{` → close.
fn bad_json(socket: &Path) -> Check {
    let name = "bad_json";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let _ = raw.send(&frame(b"{"));
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `version_mismatch`: post-handshake request with `"v": 2` →
/// `Error/VersionMismatch` for that id, then close (`01-protocol.md` §4;
/// `06-ramenctl.md` §4). A wrong-`v` `Hello` has no id and gets a `Fault`
/// instead — that case is covered by the supervisor's own fatal-violation
/// tests.
fn version_mismatch(socket: &Path, token: &str) -> Check {
    let name = "version_mismatch";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let id = req_id(0);
    let bad = frame(
        json!({ "v": 2, "id": id, "op": { "type": "Whoami" } })
            .to_string()
            .as_bytes(),
    );
    let _ = raw.send(&bad);
    let (frames, close) = raw.drain_to_close();
    let signaled = frames.iter().any(|f| {
        serde_json::from_slice::<serde_json::Value>(f)
            .map(|v| {
                v.get("status").and_then(|s| s.as_str()) == Some("Error")
                    && v["error"]["code"] == "VersionMismatch"
                    && v["id"].as_str() == Some(id.as_str())
            })
            .unwrap_or(false)
    });
    if signaled && matches!(close.as_str(), "closed" | "closed (RST)") {
        check(name, true, "Error/VersionMismatch for the request id, then close")
    } else {
        check(
            name,
            false,
            format!("expected Error/VersionMismatch then close; close: {close}, frames: {frames:?}"),
        )
    }
}

/// `no_hello`: `Whoami` as first message → close.
fn no_hello(socket: &Path) -> Check {
    let name = "no_hello";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    let _ = raw.send(&whoami_request(&req_id(0)));
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `double_hello`: `Hello` after `Welcome` → close.
fn double_hello(socket: &Path, token: &str) -> Check {
    let name = "double_hello";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let _ = raw.send(&hello(token));
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `unknown_field`: request with an extra key → close.
fn unknown_field(socket: &Path, token: &str) -> Check {
    let name = "unknown_field";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let bogus = frame(
        json!({
            "v": 1,
            "id": req_id(0),
            "op": { "type": "Whoami" },
            "bogus": true,
        })
        .to_string()
        .as_bytes(),
    );
    let _ = raw.send(&bogus);
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `dup_request_id`: Whoami with id X, receive the response, then Whoami
/// with id X again → close. Request ids are single-use for the lifetime of
/// the connection (`01-protocol.md` §3), so the second use is a fatal
/// violation — deterministically, in-flight or terminal.
fn dup_request_id(socket: &Path, token: &str) -> Check {
    let name = "dup_request_id";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let _ = raw.send(&whoami_request(&req_id(0)));
    let first = match raw.read_frame() {
        Ok(Some(f)) => f,
        Ok(None) => return check(name, false, "closed before first response"),
        Err(e) => return check(name, false, format!("read error: {e}")),
    };
    let v: serde_json::Value = match serde_json::from_slice(&first) {
        Ok(v) => v,
        Err(e) => return check(name, false, format!("bad response: {e}")),
    };
    if v["status"] != "Ok" {
        return check(name, false, format!("first Whoami not Ok: {v}"));
    }
    // Same id again: fatal, regardless of the first request being terminal.
    let _ = raw.send(&whoami_request(&req_id(0)));
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `unknown_op`: `{"type":"Frobnicate"}` → close (unknown enum variant).
fn unknown_op(socket: &Path, token: &str) -> Check {
    let name = "unknown_op";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let bad = frame(
        json!({
            "v": 1,
            "id": req_id(0),
            "op": { "type": "Frobnicate" },
        })
        .to_string()
        .as_bytes(),
    );
    let _ = raw.send(&bad);
    let (frames, close) = raw.drain_to_close();
    closed_pass(name, &frames, &close)
}

/// `concurrent`: 16 concurrent `Whoami` → 16 correctly matched responses.
fn concurrent(socket: &Path, token: &str) -> Check {
    let name = "concurrent";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }
    let ids: Vec<String> = (0..16u8).map(req_id).collect();
    let mut burst = Vec::new();
    for id in &ids {
        burst.extend(whoami_request(id));
    }
    if raw.send(&burst).is_err() {
        return check(name, false, "burst write failed");
    }
    match collect_responses(&mut raw, 16) {
        Ok(resps) => {
            let mut got: Vec<&str> = resps
                .iter()
                .filter_map(|v| v["id"].as_str())
                .collect();
            let mut want: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
            got.sort();
            want.sort();
            let all_ok = resps.iter().all(|v| v["status"] == "Ok");
            if got == want && all_ok {
                check(name, true, "16 concurrent Whoami, all matched by id")
            } else {
                check(
                    name,
                    false,
                    format!("id mismatch (got {got:?}, want {want:?}); all_ok={all_ok}"),
                )
            }
        }
        Err(d) => check(name, false, d),
    }
}

/// `out_of_order`: concurrent ops with varied latency (Whoami is fast,
/// FileWrite fsyncs) → responses matched by id, not order. With `--prefix`,
/// FileWrites to distinct paths make a mis-matched response observable
/// (the `result.path` would point at the wrong file).
fn out_of_order(socket: &Path, token: &str, prefix: Option<&Path>) -> Check {
    let name = "out_of_order";
    let mut raw = match connect_or_fail(name, socket) {
        Ok(r) => r,
        Err(c) => return c,
    };
    if raw.send(&hello(token)).is_err() || handshake_response(&mut raw).is_err() {
        return check(name, false, "handshake failed");
    }

    let b64 = base64::engine::general_purpose::STANDARD.encode(b"out-of-order\n");
    let mut ids = Vec::new();
    let mut paths: Vec<(String, String)> = Vec::new(); // (id, path)
    let mut burst = Vec::new();
    for i in 0..10u8 {
        let id = req_id(i);
        if let Some(p) = prefix {
            if i % 2 == 1 {
                let path = p.join(format!("ooo-{i}.txt"));
                paths.push((id.clone(), path.display().to_string()));
                burst.extend(filewrite_request(&id, &path.display().to_string(), &b64));
            } else {
                burst.extend(whoami_request(&id));
            }
        } else {
            burst.extend(whoami_request(&id));
        }
        ids.push(id);
    }
    if raw.send(&burst).is_err() {
        return check(name, false, "burst write failed");
    }
    let n = ids.len();
    match collect_responses(&mut raw, n) {
        Ok(resps) => {
            let mut got: Vec<&str> = resps
                .iter()
                .filter_map(|v| v["id"].as_str())
                .collect();
            let mut want: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
            got.sort();
            want.sort();
            let all_ok = resps.iter().all(|v| v["status"] == "Ok");
            // A FileWrite response must carry its own path.
            let path_ok = resps.iter().all(|v| {
                match paths.iter().find(|(id, _)| id.as_str() == v["id"].as_str().unwrap_or(""))
                {
                    Some((_, p)) => v["result"]["path"].as_str() == Some(p.as_str()),
                    None => true,
                }
            });
            if got == want && all_ok && path_ok {
                check(
                    name,
                    true,
                    if paths.is_empty() {
                        "10 concurrent Whoami, matched by id (no --prefix: whoami only)"
                    } else {
                        "mixed Whoami/FileWrite burst, matched by id, paths correct"
                    },
                )
            } else {
                check(
                    name,
                    false,
                    format!(
                        "id mismatch (got {got:?}, want {want:?}); all_ok={all_ok}; path_ok={path_ok}"
                    ),
                )
            }
        }
        Err(d) => check(name, false, d),
    }
}

/// Read exactly `n` response frames and return them as JSON values.
fn collect_responses(
    raw: &mut Raw,
    n: usize,
) -> Result<Vec<serde_json::Value>, String> {
    let mut out = Vec::new();
    for _ in 0..n {
        let f = raw
            .read_frame()
            .map_err(|e| format!("read error: {e}"))?
            .ok_or_else(|| "connection closed before all responses".to_string())?;
        let v: serde_json::Value =
            serde_json::from_slice(&f).map_err(|e| format!("bad response json: {e}"))?;
        if v.get("status").is_none() {
            return Err(format!("expected a Response, got: {v}"));
        }
        out.push(v);
    }
    Ok(out)
}
