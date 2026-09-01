//! End-to-end: the real `ramen-mint` binary against the real guard.
//!
//! The M4 expiry test built its tokens in-process via the biscuit builder
//! API (with the correct `date` clock fact), so a defect in the CLI's
//! `issue` datalog string — the part a human operator actually runs — could
//! not be caught. It was not hypothetical: the original CLI emitted
//! `check if time($t), ...`, but the guard's clock fact is `date` — an
//! unresolvable check that denied every expiry-bearing token. This test
//! shells out to the real `ramen-mint` (keygen + issue), feeds the printed
//! token to the real `Guard`, and checks the decision.
//!
//! Expiry dates are fixed instants, not now-relative: the test must behave
//! the same on any machine clock. 2100 is future for the foreseeable;
//! 2017 is past for anything after 2018.
//!
//! `07-delegation.md` §10: the `attenuate` equivalent lands with M8.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use ramen_guard::{ControlPlanePaths, FileRootKey, Guard, StdFs};
use ramen_proto::{DenialCode, Operation, WhoamiOp};

/// The package's own bin, built alongside the test binary:
/// `<target>/debug/deps/e2e_guard-<hash>` → `<target>/debug/ramen-mint`.
/// (CARGO_BIN_EXE_* is only set for bins a test *depends on*, not the
/// package's own bin, so resolve it from the test's own location.)
fn mint_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let bin = exe
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("ramen-mint"))
        .expect("test binary is under a target dir");
    assert!(bin.is_file(), "ramen-mint binary not found at {}", bin.display());
    bin
}

/// Run ramen-mint; return (stdout, stderr). Panics if the process fails to
/// spawn — a missing binary is a test-environment error, not an assertion.
fn run_mint(args: &[&str]) -> (String, String) {
    let out = Command::new(mint_bin())
        .args(args)
        .output()
        .expect("failed to spawn ramen-mint");
    (
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn keygen(key_dir: &std::path::Path) {
    let (out, err) = run_mint(&["keygen", "--dir", key_dir.to_str().unwrap()]);
    assert!(
        out.contains("private key"),
        "keygen failed: {out} {err}"
    );
}

/// Mint a token with the real CLI. `expires` is an RFC 3339 string or None.
/// Returns the base64 token (first stdout line).
fn mint_token(key_dir: &std::path::Path, expires: Option<&str>) -> String {
    let mut args: Vec<String> = vec![
        "issue".into(),
        "--dir".into(),
        key_dir.to_str().unwrap().to_string(),
        "--identity".into(),
        "agent:e2e".into(),
        "--capability".into(),
        "Whoami".into(),
        "--reversibility".into(),
        "Trivial".into(),
    ];
    if let Some(e) = expires {
        args.push("--expires".into());
        args.push(e.into());
    }
    let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let (stdout, stderr) = run_mint(&args);
    assert!(
        !stdout.is_empty(),
        "ramen-mint issue produced no token on stdout (stderr: {stderr})"
    );
    stdout.lines().next().unwrap().to_string()
}

fn whoami_guard(key_dir: &std::path::Path, state_dir: &std::path::Path) -> Guard {
    let root = FileRootKey::load(&key_dir.join("root.key.pub"))
        .expect("keygen wrote a valid root.key.pub");
    let cp = ControlPlanePaths::new(&[], state_dir).expect("control plane paths");
    Guard::new(Box::new(root), cp, Box::new(StdFs))
}

fn whoami(guard: &Guard, token: &str, now: SystemTime) -> ramen_guard::Decision {
    guard.authorize(ramen_guard::AuthzRequest {
        token,
        op: &Operation::Whoami(WhoamiOp {}),
        now,
    })
}

/// Format a unix timestamp (seconds) as an RFC 3339 UTC string.
fn rfc3339_utc(secs: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).expect("valid");
    dt.to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format")
}

// 2100-01-01T00:00:00Z — future for the foreseeable future.
const FUTURE_SECS: i64 = 4_102_444_800;
// 2017-07-14T06:13:20Z — past for any machine clock after 2018.
const PAST_SECS: i64 = 1_500_000_000;

#[test]
fn minted_token_with_future_expiry_allows() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let state_dir = tempfile::tempdir().expect("state dir");
    keygen(key_dir.path());

    let expires = rfc3339_utc(FUTURE_SECS);
    let token = mint_token(key_dir.path(), Some(&expires));

    let guard = whoami_guard(key_dir.path(), state_dir.path());
    assert_eq!(
        whoami(&guard, &token, SystemTime::now()),
        ramen_guard::Decision::Allow
    );
}

#[test]
fn minted_token_with_past_expiry_is_token_expired() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let state_dir = tempfile::tempdir().expect("state dir");
    keygen(key_dir.path());

    let expires = rfc3339_utc(PAST_SECS);
    let token = mint_token(key_dir.path(), Some(&expires));

    let guard = whoami_guard(key_dir.path(), state_dir.path());
    match whoami(&guard, &token, SystemTime::now()) {
        ramen_guard::Decision::Deny { code, .. } => {
            assert_eq!(code, DenialCode::TokenExpired);
        }
        other => panic!("expected Deny(TokenExpired), got {other:?}"),
    }
}

#[test]
fn minted_token_without_expiry_allows() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let state_dir = tempfile::tempdir().expect("state dir");
    keygen(key_dir.path());

    let token = mint_token(key_dir.path(), None);

    let guard = whoami_guard(key_dir.path(), state_dir.path());
    assert_eq!(
        whoami(&guard, &token, SystemTime::now()),
        ramen_guard::Decision::Allow
    );
}

/// Non-UTC offset: the check must compare instants, not string prefixes.
/// A +14:00 spelling puts the wall-clock string of the same instant in a
/// different lexicographic position than its UTC spelling.
#[test]
fn minted_expiry_with_non_utc_offset_compares_as_instant() {
    let key_dir = tempfile::tempdir().expect("key dir");
    let state_dir = tempfile::tempdir().expect("state dir");
    keygen(key_dir.path());

    let offset = time::UtcOffset::from_hms(14, 0, 0).expect("fixed offset");
    let expires = time::OffsetDateTime::from_unix_timestamp(FUTURE_SECS)
        .expect("valid")
        .to_offset(offset)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format");
    assert!(
        expires.ends_with("+14:00"),
        "offset should be preserved: {expires}"
    );

    let token = mint_token(key_dir.path(), Some(&expires));

    let guard = whoami_guard(key_dir.path(), state_dir.path());
    assert_eq!(
        whoami(&guard, &token, SystemTime::now()),
        ramen_guard::Decision::Allow
    );
}
