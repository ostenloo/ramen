//! Integration test harness for the ramen-supervisor binary.
//!
//! Each integration test binary is a separate crate that includes this
//! module; every binary only uses a subset of the harness, so dead code
//! warnings are expected and suppressed.
#![allow(dead_code)]
//!
//! The test binary IS the client: it connects to the supervisor's Unix
//! socket as an ad-hoc-signed binary whose code identifier (the binary's
//! absolute path) is pinned in the test config's `[peer] requirement`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ramen_audit::{Record, VerifyReport, split_frames, verify_bytes};
use ramen_proto::codec::Decoder;
use ramen_proto::messages::ClientInfo;
use ramen_proto::{Message, Operation, PROTOCOL_VERSION};
use biscuit_auth::{Algorithm, BiscuitBuilder, KeyPair};

pub fn binary_path() -> PathBuf {
    // The test executable lives at <target>/debug/deps/<name>-<hash>;
    // the supervisor bin is <target>/debug/ramen-supervisor.
    let exe = std::env::current_exe().unwrap();
    let deps = exe.parent().unwrap();
    let debug = deps.parent().unwrap();
    debug.join("ramen-supervisor")
}

/// A cloneable bundle of everything a supervisor run needs: the temp dir,
/// the socket/audit/root-key paths, and the root key material (for minting
/// test tokens).
#[derive(Clone)]
pub struct Parts {
    /// The fixture's temp dir (the `Fixture` owns the `TempDir`; this is
    /// just the path, kept cloneable for the supervisor).
    pub dir_path: PathBuf,
    pub socket: PathBuf,
    pub audit: PathBuf,
    pub root_key: PathBuf,
    pub state: PathBuf,
    /// The root *private* key PEM — test-only: the test process stands in
    /// for the minter. The supervisor itself never sees this.
    pub root_priv_pem: String,
}

impl Parts {
    /// A complete, valid config body pinning `requirement`.
    pub fn body(&self, requirement: &str) -> String {
        format!(
            r#"
socket_path = "{}"
audit_path  = "{}"
root_key_path = "{}"
state_dir   = "{}"

[peer]
requirement = '{}'
"#,
            self.socket.display(),
            self.audit.display(),
            self.root_key.display(),
            self.state.display(),
            requirement,
        )
    }

    /// A valid config body pinning `requirement`, with an explicit
    /// `allowed_prefixes` list (the supervisor-level `FileWrite` bound,
    /// `05-operations.md` M6). The key is top-level: it is inserted before
    /// the `[peer]` header, where appending would put it inside the table.
    pub fn body_with_prefixes(&self, requirement: &str, prefixes: &[PathBuf]) -> String {
        let list: Vec<String> = prefixes
            .iter()
            .map(|p| format!("\"{}\"", p.display()))
            .collect();
        self.body(requirement)
            .replace("\n[peer]", &format!("\nallowed_prefixes = [{}]\n\n[peer]", list.join(", ")))
    }

    pub fn valid_body(&self) -> String {
        self.body(&format!("identifier \"{}\"", test_binary_identifier()))
    }

    pub fn write_config(&self, body: &str) -> PathBuf {
        let p = self.dir_path.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }
}

/// Test fixtures: a fresh temp dir with a root keypair.
pub struct Fixture {
    /// Keeps the temp dir alive for the fixture's lifetime.
    pub dir: tempfile::TempDir,
    pub parts: Parts,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_path = dir.path().to_path_buf();
        let socket = dir_path.join("sup.sock");
        let audit = dir_path.join("audit.log");
        let root_key = dir_path.join("root.pub");
        let state = dir_path.join("state");
        let root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let pub_pem = root.public().to_pem().unwrap();
        let priv_pem = root.to_private_key_pem().unwrap().to_string();
        std::fs::write(&root_key, &pub_pem).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Fixture {
            dir,
            parts: Parts {
                dir_path,
                socket,
                audit,
                root_key,
                state,
                root_priv_pem: priv_pem,
            },
        }
    }
}

/// Spawn the supervisor with `config`, wait for it to exit, and return
/// (status, combined stdout). For startup-failure tests.
pub fn run_to_exit(config: &Path) -> (std::process::ExitStatus, String) {
    let out = Command::new(binary_path())
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    let mut s = String::from_utf8_lossy(&out.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status, s)
}

pub struct Supervisor {
    pub parts: Parts,
    pub socket: PathBuf,
    pub audit: PathBuf,
    pub child: Child,
    /// Keeps the fixture's temp dir alive when the fixture itself is gone
    /// (e.g. `Supervisor::start()`).
    keep: Option<tempfile::TempDir>,
    logs: mpsc::Receiver<String>,
}

impl Supervisor {
    /// Start a supervisor with the default test config and wait until it
    /// accepts connections.
    pub fn start() -> Self {
        let f = Fixture::new();
        let keep = Some(f.dir);
        let parts = f.parts;
        Self::start_with_parts(&parts, keep)
    }

    /// Start with an explicit config body (paths must reference the
    /// fixture's dir).
    pub fn start_with_body(fx: &Fixture, body: &str) -> Self {
        Self::start_with_body_env(fx, body, &[])
    }

    /// Start with an explicit config body and extra environment variables
    /// (test hooks, e.g. `RAMEN_TEST_PAUSE_AFTER_AUTHORIZED`).
    pub fn start_with_body_env(fx: &Fixture, body: &str, env: &[(&str, &str)]) -> Self {
        let config = fx.parts.write_config(body);
        Self::start_with_parts_cfg(&fx.parts, &config, None, env)
    }

    /// Restart a supervisor on the same paths (same audit log, same socket
    /// path). The previous instance must be dead.
    pub fn restart(&self) -> Self {
        let config = self.parts.write_config(&self.parts.valid_body());
        Self::start_with_parts_cfg(&self.parts, &config, None, &[])
    }

    fn start_with_parts(parts: &Parts, keep: Option<tempfile::TempDir>) -> Self {
        let config = parts.write_config(&parts.valid_body());
        Self::start_with_parts_cfg(parts, &config, keep, &[])
    }

    fn start_with_parts_cfg(
        parts: &Parts,
        config: &Path,
        keep: Option<tempfile::TempDir>,
        env: &[(&str, &str)],
    ) -> Self {
        let bin = binary_path();
        let mut cmd = Command::new(&bin);
        cmd.arg("--config")
            .arg(config)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));

        // Drain stdout in a thread so a log flood can never block the
        // supervisor on a full pipe.
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            let _ = tx.send(s);
        });

        let mut this = Self {
            socket: parts.socket.clone(),
            audit: parts.audit.clone(),
            parts: parts.clone(),
            child,
            keep,
            logs: rx,
        };

        // Wait for readiness: connectable socket, or the process died.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(Some(status)) = this.child.try_wait() {
                panic!(
                    "supervisor exited early with {status}:\n{}",
                    this.logs_drain()
                );
            }
            if UnixStream::connect(&this.socket).is_ok() {
                return this;
            }
            if Instant::now() > deadline {
                panic!(
                    "supervisor did not start listening on {}:\n{}",
                    this.socket.display(),
                    this.logs_drain()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn logs_drain(&self) -> String {
        let mut out = String::new();
        while let Ok(chunk) = self.logs.try_recv() {
            out.push_str(&chunk);
        }
        out
    }

    /// Mint a token for `identity` with the given capability facts.
    ///
    /// Every token also carries `reversibility_allowed("Trivial")`, since
    /// both v0 operations are `Trivial` (`05-operations.md`) and the guard
    /// denies operations whose reversibility the token does not allow
    /// (`04-guard.md` §5).
    pub fn token(&self, identity: &str, capabilities: &[&str]) -> String {
        self.token_with_extra(identity, capabilities, "")
    }

    /// Mint a `FileWrite` token whose `allowed_prefix` fact covers
    /// `prefix` (the canonical form the guard compares against).
    pub fn filewrite_token(&self, identity: &str, prefix: &str) -> String {
        self.token_with_extra(
            identity,
            &["FileWrite"],
            &format!("allowed_prefix(\"FileWrite\", \"{prefix}\");\n"),
        )
    }

    /// Mint a token with additional authority-block facts (e.g.
    /// `allowed_prefix(...)`).
    pub fn token_with_extra(&self, identity: &str, capabilities: &[&str], extra: &str) -> String {
        let root = KeyPair::from_private_key_pem(&self.parts.root_priv_pem).unwrap();
        let mut code = format!("identity(\"{identity}\");\n");
        for c in capabilities {
            code.push_str(&format!("capability(\"{c}\");\n"));
        }
        code.push_str("reversibility_allowed(\"Trivial\");\n");
        code.push_str(extra);
        let biscuit = BiscuitBuilder::new()
            .code(&code)
            .unwrap()
            .build(&root)
            .unwrap();
        biscuit.to_base64().unwrap()
    }

    /// A token signed with a *different* key.
    pub fn foreign_token(&self) -> String {
        let other = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let biscuit = BiscuitBuilder::new()
            .code("identity(\"agent:evil\");\ncapability(\"Whoami\");\n")
            .unwrap()
            .build(&other)
            .unwrap();
        biscuit.to_base64().unwrap()
    }

    /// Send SIGTERM, wait, and return the exit status (asserts exit 0).
    pub fn terminate_and_wait(&mut self) -> std::process::ExitStatus {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let status = self.child.wait().unwrap();
        assert!(
            status.success(),
            "supervisor should exit 0 on SIGTERM, got {status}:\n{}",
            self.logs_drain()
        );
        status
    }

    /// Send SIGKILL, wait, and return the exit status.
    pub fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        self.child.kill().unwrap();
        self.child.wait().unwrap()
    }

    /// Wait for the supervisor to exit on its own (e.g. the invariant-4
    /// fatal audit failure, `EXIT_AUDIT_UNAVAILABLE`) and return the status.
    pub fn wait_exit(&mut self) -> std::process::ExitStatus {
        self.child.wait().unwrap()
    }

    /// All audit records currently in the log file.
    pub fn audit_records(&self) -> Vec<Record> {
        read_audit_records(&self.audit)
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn read_audit_records(path: &Path) -> Vec<Record> {
    let bytes = std::fs::read(path).expect("audit log readable");
    let split = split_frames(&bytes);
    assert_eq!(
        split.tail, 0,
        "audit log has a torn tail ({} trailing bytes)",
        split.tail
    );
    split
        .frames
        .iter()
        .map(|(s, e)| &bytes[*s + 4..*e])
        .map(|f| serde_json::from_slice::<Record>(f).expect("audit frame decodes"))
        .collect()
}

/// The audit kinds of all records, for compact assertions.
pub fn audit_kinds(path: &Path) -> Vec<ramen_audit::RecordKind> {
    read_audit_records(path)
        .into_iter()
        .map(|r| match r {
            Record::Event(e) => e.kind,
            Record::LogHeader(_) => panic!("LogHeader in kinds list"),
        })
        .collect()
}

pub fn verify_file(path: &Path) -> VerifyReport {
    verify_bytes(&std::fs::read(path).expect("audit log readable"))
}

pub fn assert_chain_valid(path: &Path) {
    let report = verify_file(path);
    assert!(
        report.ok(),
        "audit chain invalid at {}: {report:?}",
        path.display()
    );
}

/// A synchronous Unix socket client speaking the ramen wire protocol.
pub struct Client {
    stream: UnixStream,
    decoder: Decoder,
}

impl Client {
    pub fn connect(path: &Path) -> Self {
        let stream = UnixStream::connect(path).expect("connect to supervisor socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("set read timeout");
        Client {
            stream,
            decoder: Decoder::new(),
        }
    }

    /// Send one message (framed).
    pub fn send(&mut self, msg: &Message) {
        let mut buf = Vec::new();
        msg.encode(&mut buf).expect("encode message");
        self.stream.write_all(&buf).expect("write frame");
    }

    /// Send raw bytes (for malformed-frame tests).
    pub fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("write raw bytes");
    }

    /// Read one message; None on clean EOF. A frame already buffered by a
    /// previous read is returned before blocking again.
    pub fn recv(&mut self) -> Option<Message> {
        if let Ok(Some(frame)) = self.decoder.next_frame() {
            return Some(Message::decode(&frame).expect("decode message"));
        }
        let mut buf = [0u8; 65536];
        let n = self.stream.read(&mut buf).expect("read frame");
        if n == 0 {
            return None;
        }
        self.decoder.feed(&buf[..n]).expect("feed decoder");
        let frame = self.decoder.next_frame().expect("next frame")?;
        Some(Message::decode(&frame).expect("decode message"))
    }

    /// Perform the handshake with a token; returns the session id.
    pub fn hello(&mut self, token: &str) -> ramen_proto::SessionId {
        let hello = Message::Hello(ramen_proto::Hello::new(
            token.to_string(),
            ClientInfo {
                name: "ramen-supervisor-test".into(),
                version: "0.0.0-test".into(),
            },
        ));
        self.send(&hello);
        match self.recv() {
            Some(Message::Welcome(w)) => w.session,
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    /// Perform the handshake and return the raw response (for Fault cases).
    pub fn hello_raw(&mut self, token: &str) -> Option<Message> {
        let hello = Message::Hello(ramen_proto::Hello::new(
            token.to_string(),
            ClientInfo {
                name: "ramen-supervisor-test".into(),
                version: "0.0.0-test".into(),
            },
        ));
        self.send(&hello);
        self.recv()
    }

    /// Send a request and read the corresponding response.
    pub fn request(&mut self, op: Operation) -> (ramen_proto::RequestId, ramen_proto::Response) {
        let req = ramen_proto::Request::new(op);
        let id = req.id;
        self.send(&Message::Request(req));
        let resp = match self.recv() {
            Some(Message::Response(r)) => r,
            other => panic!("expected Response, got {other:?}"),
        };
        assert_eq!(response_id(&resp), id, "response must match the request id");
        (id, resp)
    }

    /// Send a request without reading the response (for burst tests).
    pub fn send_request_only(&mut self, op: Operation) {
        self.send(&Message::Request(ramen_proto::Request::new(op)));
    }
}

/// Extract the request id from any `Response` variant.
pub fn response_id(r: &ramen_proto::Response) -> ramen_proto::RequestId {
    match r {
        ramen_proto::Response::Ok { id, .. }
        | ramen_proto::Response::Denied { id, .. }
        | ramen_proto::Response::Error { id, .. } => *id,
    }
}

/// The code identifier the test binary itself is signed with (ad-hoc).
pub fn test_binary_identifier() -> String {
    use ramen_supervisor::platform::signing_info_for_path;
    let exe = std::env::current_exe().expect("current exe");
    let info = signing_info_for_path(&exe)
        .expect("test binary must be signed (ad-hoc at minimum)");
    info.signing_id
        .expect("ad-hoc signed binary must have an identifier")
}

// Silence unused warnings for constants the tests may not all use.
pub const _PROTO_VERSION: u16 = PROTOCOL_VERSION;
