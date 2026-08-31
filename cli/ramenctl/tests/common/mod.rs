//! Supervisor test harness for the `ramenctl` integration tests.
//!
//! The supervisor's `[peer] requirement` pins the **ramenctl binary's**
//! code-signing identifier (ad-hoc on macOS): the test binary drives
//! `ramenctl`, which is the process that actually connects.

#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use biscuit_auth::{Algorithm, BiscuitBuilder, KeyPair};

pub fn supervisor_binary_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let debug = exe.parent().unwrap().parent().unwrap();
    debug.join("ramen-supervisor")
}

pub fn ramenctl_binary_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let debug = exe.parent().unwrap().parent().unwrap();
    debug.join("ramenctl")
}

#[derive(Clone)]
pub struct Parts {
    pub dir_path: PathBuf,
    pub socket: PathBuf,
    pub audit: PathBuf,
    pub root_key: PathBuf,
    pub state: PathBuf,
    pub root_priv_pem: String,
}

impl Parts {
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

    /// Pins the ramenctl binary's signing identifier.
    pub fn ramenctl_body(&self, prefixes: &[PathBuf]) -> String {
        let info = ramen_supervisor::platform::signing_info_for_path(&ramenctl_binary_path())
            .expect("ramenctl binary must be signed (ad-hoc at minimum)");
        let id = info
            .signing_id
            .expect("ad-hoc signed binary must have an identifier");
        self.body(&format!("identifier \"{id}\""), prefixes)
    }

    /// Pins the *test binary's* signing identifier (for raw-socket tests
    /// that connect from the test process itself).
    pub fn testbin_body(&self, prefixes: &[PathBuf]) -> String {
        let exe = std::env::current_exe().unwrap();
        let info = ramen_supervisor::platform::signing_info_for_path(&exe)
            .expect("test binary must be signed (ad-hoc at minimum)");
        let id = info
            .signing_id
            .expect("ad-hoc signed binary must have an identifier");
        self.body(&format!("identifier \"{id}\""), prefixes)
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
    /// Start a supervisor pinning the ramenctl binary's identifier, with
    /// optional supervisor-level `allowed_prefixes` and env hooks.
    pub fn start_ramenctl(prefixes: Vec<PathBuf>, env: Vec<(&str, &str)>) -> Self {
        Self::start_with(|parts: &Parts, prefixes: &[PathBuf]| parts.ramenctl_body(prefixes), prefixes, env)
    }

    /// Start a supervisor pinning the test binary's identifier.
    pub fn start_testbin(prefixes: Vec<PathBuf>) -> Self {
        Self::start_with(|parts: &Parts, prefixes: &[PathBuf]| parts.testbin_body(prefixes), prefixes, vec![])
    }

    fn start_with(
        make_body: impl Fn(&Parts, &[PathBuf]) -> String + Send + 'static,
        prefixes: Vec<PathBuf>,
        env: Vec<(&str, &str)>,
    ) -> Self {
        let f = Fixture::new();
        let keep = Some(f.dir);
        let parts = f.parts;
        let config = parts.write_config(&make_body(&parts, &prefixes));
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

    /// Mint a token for `identity` with the given capability facts plus
    /// `extra` raw code (e.g. `allowed_prefix(...)`). Every token carries
    /// `reversibility_allowed("Trivial")`.
    pub fn token(&self, identity: &str, capabilities: &[&str], extra: &str) -> String {
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

    /// Send SIGKILL, wait, return the status.
    pub fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        self.child.kill().unwrap();
        self.child.wait().unwrap()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parse the audit log into records (no torn tail).
pub fn read_audit_records(path: &Path) -> Vec<ramen_audit::Record> {
    let bytes = std::fs::read(path).expect("audit log readable");
    let split = ramen_audit::split_frames(&bytes);
    assert_eq!(
        split.tail, 0,
        "audit log has a torn tail ({} trailing bytes)",
        split.tail
    );
    split
        .frames
        .iter()
        .map(|(s, e)| &bytes[*s + 4..*e])
        .map(|f| serde_json::from_slice::<ramen_audit::Record>(f).expect("audit frame decodes"))
        .collect()
}
