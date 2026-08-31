//! M7 acceptance tests for `ramenctl` (06-ramenctl.md §5).
//!
//! - `ping` completes a handshake and exits 0.
//! - `whoami` prints identity and capabilities matching a token minted with
//!   known contents.
//! - `write` writes a file; content on disk matches; a restore handle is
//!   printed.
//! - `write` to a denied path exits 1, prints the denial code and `audit_seq`,
//!   and that `audit_seq` resolves to a matching `Denied` record.
//! - Supervisor stopped → exit 2, not 1.
//! - `--json` output on every command parses as JSON, no ANSI escapes.
//! - `conform` passes every check against a running supervisor.
//! - After a full `conform` run, `ramen-audit-verify` exits 0 or 1 — never 2.
//!
//! The supervisor's `[peer] requirement` pins the *ramenctl binary's*
//! code-signing identifier (ad-hoc on macOS): the test binary runs ramenctl,
//! it does not connect itself.

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

fn ramenctl_path() -> PathBuf {
    // tests/cli-<hash> lives at <target>/debug/deps/cli-<hash>; the bin is
    // <target>/debug/ramenctl.
    let exe = std::env::current_exe().unwrap();
    let debug = exe.parent().unwrap().parent().unwrap();
    debug.join("ramenctl")
}

fn audit_verify_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let debug = exe.parent().unwrap().parent().unwrap();
    debug.join("ramen-audit-verify")
}

struct Ctl {
    _workdir: tempfile::TempDir,
    sup: common::Supervisor,
    token_file: PathBuf,
    workdir: PathBuf,
}

/// Supervisor with `workdir` as the only allowed prefix, plus a token file
/// granting Whoami + FileWrite (under `workdir`) to `agent:ctl`.
fn ctl() -> Ctl {
    let workdir = tempfile::tempdir().unwrap();
    let work = workdir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let work = work.canonicalize().unwrap();

    let (sup, token_file, work) = std::thread::spawn(move || {
        let sup = common::Supervisor::start_ramenctl(vec![work.clone()], vec![]);
        let token = sup
            .token(
                "agent:ctl",
                &["Whoami", "FileWrite"],
                &format!("allowed_prefix(\"FileWrite\", \"{}\");\n", work.display()),
            );
        let token_file = sup.parts.dir_path.join("token.b64");
        std::fs::write(&token_file, &token).unwrap();
        (sup, token_file, work)
    })
    .join()
    .unwrap();

    Ctl {
        _workdir: workdir,
        sup,
        token_file,
        workdir: work,
    }
}

fn run_ctl(ctl: &Ctl, json: bool, args: &[&str]) -> Output {
    let mut cmd = Command::new(ramenctl_path());
    cmd.arg("--socket")
        .arg(&ctl.sup.socket)
        .arg("--token")
        .arg(&ctl.token_file);
    if json {
        cmd.arg("--json");
    }
    for a in args {
        cmd.arg(a);
    }
    cmd.output().unwrap()
}

/// `--json` output parses as JSON and contains no ANSI escapes.
fn assert_json(stdout: &str) {
    assert!(
        !stdout.contains("\u{1b}["),
        "ANSI escape in --json output: {stdout:?}"
    );
    serde_json::from_str::<serde_json::Value>(stdout)
        .unwrap_or_else(|e| panic!("--json output is not valid JSON ({e}): {stdout:?}"));
}

#[test]
fn ping_completes_handshake_and_exits_0() {
    let ctl = ctl();
    let out = run_ctl(&ctl, false, &["ping"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ok"), "stdout: {stdout}");

    let out = run_ctl(&ctl, true, &["ping"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_json(&stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["session"].as_str().is_some());
}

#[test]
fn whoami_prints_identity_and_capabilities() {
    let ctl = ctl();
    let out = run_ctl(&ctl, false, &["whoami"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("identity:    agent:ctl"), "stdout: {stdout}");
    assert!(stdout.contains("Whoami (Trivial)"), "stdout: {stdout}");
    assert!(
        stdout.contains("FileWrite (Trivial)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!("path_prefix: {}", ctl.workdir.display())),
        "stdout: {stdout}"
    );

    // --json: the raw result value.
    let out = run_ctl(&ctl, true, &["whoami"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_json(&stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["identity"], "agent:ctl");
    let caps = v["capabilities"].as_array().unwrap();
    let names: Vec<&str> = caps
        .iter()
        .map(|c| c["op"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["FileWrite", "Whoami"]); // alphabetical (BTreeMap)
}

#[test]
fn write_writes_file_and_prints_restore_handle() {
    let ctl = ctl();
    let target = ctl.workdir.join("notes.md");
    let target_s = target.display().to_string();

    // A new file: Create mode (Overwrite snapshots the original first, so it
    // requires an existing target).
    let content = "the quick brown ramen\n";
    let out = run_ctl(
        &ctl,
        false,
        &[
            "write",
            &target_s,
            "--create",
            "--content",
            content,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("wrote {target_s} ({} bytes)", content.len())),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("restore:"), "stdout: {stdout}");
    assert!(
        std::fs::read_to_string(&target).unwrap() == content,
        "content on disk does not match"
    );

    // stdin content
    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&ctl.sup.socket)
        .arg("--token")
        .arg(&ctl.token_file)
        .arg("write")
        .arg(&target_s)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    // Write via the child's stdin in a thread to avoid deadlock on large
    // content (content is small, but be safe).
    let mut child = out;
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"second write\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "second write\n"
    );

    // --json
    let out = run_ctl(
        &ctl,
        true,
        &["write", &target_s, "--content", "x"],
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_json(&stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["path"], target_s);
    assert!(v["restore"]["handle"].as_str().is_some());
}

#[test]
fn write_denied_exits_1_with_code_and_audit_seq() {
    let ctl = ctl();
    // A token without the FileWrite capability: the write is denied.
    let no_write_token = ctl
        .sup
        .token("agent:readonly", &["Whoami"], "");
    let token_file = ctl.sup.parts.dir_path.join("ro-token.b64");
    std::fs::write(&token_file, &no_write_token).unwrap();

    let target = ctl.workdir.join("secret.md");
    let target_s = target.display().to_string();
    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&ctl.sup.socket)
        .arg("--token")
        .arg(&token_file)
        .arg("write")
        .arg(&target_s)
        .arg("--content")
        .arg("nope")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "denial is exit 1, not 2; stderr: {:?}",
        out.stderr
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("denied: CapabilityNotGranted"),
        "stdout: {stdout}"
    );
    let seq_line = stdout
        .lines()
        .find(|l| l.starts_with("audit_seq:"))
        .expect("audit_seq printed");
    let audit_seq: u64 = seq_line
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap();

    // The audit_seq resolves to a matching Denied record.
    let records = common::read_audit_records(&ctl.sup.audit);
    let rec = records
        .iter()
        .find(|r| r.seq() == audit_seq)
        .unwrap_or_else(|| panic!("no record with seq {audit_seq}"));
    let ramen_audit::Record::Event(e) = rec else {
        panic!("expected an event record with seq {audit_seq}, got {rec:?}");
    };
    assert_eq!(e.kind, ramen_audit::RecordKind::Denied);
    assert_eq!(e.identity.as_deref(), Some("agent:readonly"));

    // And the file was not written.
    assert!(!target.exists());
}

#[test]
fn supervisor_stopped_exits_2_not_1() {
    let mut ctl = ctl();
    let socket = ctl.sup.socket.clone();
    ctl.sup.kill_and_wait();

    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&socket)
        .arg("--token")
        .arg(&ctl.token_file)
        .arg("ping")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "dead socket is a transport error (2), not a denial (1); stderr: {:?}",
        out.stderr
    );

    // --json: machine-readable transport error.
    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&socket)
        .arg("--token")
        .arg(&ctl.token_file)
        .arg("--json")
        .arg("whoami")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value =
        serde_json::from_str(stderr.trim()).unwrap_or_else(|e| {
            panic!("--json transport error on stderr is not JSON ({e}): {stderr:?}")
        });
    assert_eq!(v["error"], "protocol");
}

#[test]
fn usage_errors_exit_3() {
    let ctl = ctl();
    // No subcommand.
    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&ctl.sup.socket)
        .arg("--token")
        .arg(&ctl.token_file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));

    // Unreadable token file.
    let out = run_ctl(&ctl, false, &["ping"]); // sanity: works
    assert_eq!(out.status.code(), Some(0));
    let missing = ctl.sup.parts.dir_path.join("missing.b64");
    let out = Command::new(ramenctl_path())
        .arg("--socket")
        .arg(&ctl.sup.socket)
        .arg("--token")
        .arg(&missing)
        .arg("ping")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn conform_passes_all_checks() {
    let ctl = ctl();
    let out = run_ctl(&ctl, false, &["conform", "--prefix", &ctl.workdir.display().to_string()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "conform failed:\n{stdout}\n{stderr}"
    );
    assert!(stdout.contains("13/13 checks passed"), "stdout: {stdout}");

    // --json: machine-readable, no ANSI.
    let out = run_ctl(&ctl, true, &["conform"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {:?}", out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_json(&stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["passed"], v["total"]);
    for c in v["checks"].as_array().unwrap() {
        assert_eq!(c["pass"], true, "check failed: {c}");
    }
}

#[test]
fn audit_log_survives_hostile_conform_run() {
    // The single most important assertion in M7: a conformance run consists
    // entirely of hostile input and must not be able to corrupt the chain.
    let ctl = ctl();
    let out = run_ctl(&ctl, false, &["conform", "--prefix", &ctl.workdir.display().to_string()]);
    assert_eq!(out.status.code(), Some(0));

    // Let the supervisor flush (SessionClosed etc.) before inspecting.
    std::thread::sleep(std::time::Duration::from_millis(200));

    let verify = Command::new(audit_verify_path())
        .arg(&ctl.sup.audit)
        .output()
        .unwrap();
    assert!(
        matches!(verify.status.code(), Some(0) | Some(1)),
        "ramen-audit-verify must exit 0 or 1 after a conform run — never 2; \
         got {:?}; stdout: {:?}; stderr: {:?}",
        verify.status.code(),
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn write_preflights_content_size_before_connecting() {
    let ctl = ctl();
    // One byte over the supervisor's 256 KiB content cap.
    let big = "x".repeat(256 * 1024 + 1);
    let target = ctl.workdir.join("big.txt");
    let target_s = target.display().to_string();
    let out = run_ctl(
        &ctl,
        false,
        &["write", &target_s, "--create", "--content", &big],
    );
    // A usage error, not a round trip: the caller's input is at fault, so it
    // fails locally with exit 3 before any connection is opened.
    assert_eq!(out.status.code(), Some(3), "stderr: {:?}", out.stderr);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("256 KiB"),
        "the preflight message should name the cap; stderr: {stderr}"
    );
    assert!(!target.exists(), "nothing may be written");
}
