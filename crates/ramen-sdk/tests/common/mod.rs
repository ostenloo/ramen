//! Minimal supervisor test harness for the `ramen-sdk` client tests.
//!
//! The test binary IS the client: it connects to the supervisor's Unix
//! socket as an ad-hoc-signed binary whose code identifier (the binary's
//! absolute path) is pinned in the test config's `[peer] requirement`.
//!
//! This is a test-only harness; the `ramen-sdk` library itself depends on
//! neither `ramen-supervisor` nor `ramen-audit`.

#![allow(dead_code)]

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use biscuit_auth::{Algorithm, BiscuitBuilder, KeyPair};

use base64::Engine;

pub fn supervisor_binary_path() -> PathBuf {
    // The test executable lives at <target>/debug/deps/<name>-<hash>;
    // the supervisor bin is <target>/debug/ramen-supervisor.
    let exe = std::env::current_exe().expect("current exe");
    let deps = exe.parent().unwrap();
    let debug = deps.parent().unwrap();
    debug.join("ramen-supervisor")
}

#[derive(Clone)]
pub struct Parts {
    pub dir_path: PathBuf,
    pub socket: PathBuf,
    pub audit: PathBuf,
    pub root_key: PathBuf,
    pub state: PathBuf,
    /// Root *private* key PEM — test-only: the test process stands in for
    /// the minter. The supervisor never sees it.
    pub root_priv_pem: String,
}

impl Parts {
    /// A complete, valid config body pinning `requirement`, with an
    /// explicit `allowed_prefixes` (the supervisor-level `FileWrite` bound).
    pub fn body(&self, requirement: &str, prefixes: &[PathBuf]) -> String {
        let list: Vec<String> = prefixes
            .iter()
            .map(|p| format!("\"{}\"", p.display()))
            .collect();
        format!(
            r#"
socket_path = "{}"
audit_path  = "{}"
root_key_path = "{}"
state_dir   = "{}"
allowed_prefixes = [{}]

[peer]
requirement = '{}'
"#,
            self.socket.display(),
            self.audit.display(),
            self.root_key.display(),
            self.state.display(),
            list.join(", "),
            requirement,
        )
    }

    pub fn valid_body(&self, prefixes: &[PathBuf]) -> String {
        self.body(&format!("identifier \"{}\"", test_binary_identifier()), prefixes)
    }

    pub fn write_config(&self, body: &str) -> PathBuf {
        let p = self.dir_path.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }
}

pub struct Fixture {
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
        std::fs::write(&root_key, root.public().to_pem().unwrap()).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        Fixture {
            dir,
            parts: Parts {
                dir_path,
                socket,
                audit,
                root_key,
                state,
                root_priv_pem: root.to_private_key_pem().unwrap().to_string(),
            },
        }
    }
}

pub struct Supervisor {
    pub parts: Parts,
    pub socket: PathBuf,
    pub audit: PathBuf,
    pub child: Child,
    keep: Option<tempfile::TempDir>,
    logs: mpsc::Receiver<String>,
}

impl Supervisor {
    /// Start a supervisor with the default test config (pinning this test
    /// binary's signing identifier), optional supervisor-level
    /// `allowed_prefixes`, and optional extra environment (test hooks).
    pub fn start(prefixes: Vec<PathBuf>, env: Vec<(&str, &str)>) -> Self {
        let f = Fixture::new();
        let keep = Some(f.dir);
        let parts = f.parts;
        let config = parts.write_config(&parts.valid_body(&prefixes));
        let bin = supervisor_binary_path();
        let mut cmd = Command::new(&bin);
        cmd.arg("--config")
            .arg(&config)
            .env("RUST_LOG", "debug")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()));

        // Drain stdout so a log flood can never block the supervisor on a
        // full pipe.
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stdout.read_to_string(&mut s);
            let _ = tx.send(s);
        });

        let mut this = Self {
            parts: parts.clone(),
            socket: parts.socket.clone(),
            audit: parts.audit.clone(),
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
            if std::os::unix::net::UnixStream::connect(&this.socket).is_ok() {
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

    /// Mint a token for `identity` with the given capability facts. Every
    /// token also carries `reversibility_allowed("Trivial")`, since both v0
    /// operations are Trivial and the guard denies operations whose
    /// reversibility the token does not allow.
    pub fn token(&self, identity: &str, capabilities: &[&str], extra: &str) -> String {
        let root =
            KeyPair::from_private_key_pem(&self.parts.root_priv_pem).unwrap();
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

    /// A token that grants `Whoami` only.
    pub fn whoami_token(&self, identity: &str) -> String {
        self.token(identity, &["Whoami"], "")
    }

    /// A `FileWrite` token whose `allowed_prefix` fact covers `prefix`.
    pub fn filewrite_token(&self, identity: &str, prefix: &str) -> String {
        self.token(
            identity,
            &["FileWrite"],
            &format!("allowed_prefix(\"FileWrite\", \"{prefix}\");\n"),
        )
    }

    /// Send SIGKILL, wait, return the status.
    pub fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        self.child.kill().unwrap();
        self.child.wait().unwrap()
    }

    /// `true` once the audit log contains an `Authorized` record (proof a
    /// request passed the guard and its effect was about to run).
    pub fn audit_contains_authorized(&self) -> bool {
        let bytes = match std::fs::read(&self.audit) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let split = ramen_audit::split_frames(&bytes);
        split.frames.iter().any(|(s, e)| {
            bytes[*s + 4..*e]
                .windows(12)
                .any(|w| w == b"\"Authorized\"")
        })
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

/// Build a base64 (standard, padded) FileWrite operation payload.
pub fn filewrite_op(
    path: &str,
    content: &str,
    mode: ramen_sdk::WriteMode,
) -> ramen_sdk::Operation {
    let content_b64 = base64::engine::general_purpose::STANDARD
        .encode(content.as_bytes());
    ramen_sdk::Operation::FileWrite(ramen_sdk::FileWriteOp {
        path: path.to_string(),
        content_b64,
        mode,
    })
}
