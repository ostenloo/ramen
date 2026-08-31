//! Startup behavior (`03-supervisor.md` §1, §7): strict startup — any
//! failure aborts with a non-zero exit and a message on stderr.

mod common;

use common::run_to_exit;
use common::Fixture;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// The supervisor starts, creates the socket at 0600, and accepts.
#[test]
fn starts_and_listens_with_0600_socket() {
    let sup = common::Supervisor::start();
    let mode = std::fs::metadata(&sup.socket).unwrap().mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(sup);
}

/// No `--config` / bad argument: non-zero exit, usage on stderr.
#[test]
fn rejects_missing_config_argument() {
    let bin = common::binary_path();
    let out = std::process::Command::new(&bin)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage"), "stderr: {stderr}");
}

#[test]
fn refuses_world_writable_config() {
    let f = Fixture::new();
    let config = f.parts.write_config(&f.parts.valid_body());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o646)).unwrap();
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.to_lowercase().contains("startup failed"), "{out}");
    assert!(out.contains("world-writable"), "{out}");
    // No socket must have been created.
    assert!(!f.parts.socket.exists());
}

#[test]
fn refuses_group_writable_config() {
    let f = Fixture::new();
    let config = f.parts.write_config(&f.parts.valid_body());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664)).unwrap();
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("writable"), "{out}");
    assert!(!f.parts.socket.exists());
}

#[test]
fn refuses_socket_directory_group_writable() {
    let f = Fixture::new();
    // Make the socket's parent dir group-writable.
    std::fs::set_permissions(
        f.parts.dir_path.as_path(),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let config = f.parts.write_config(&f.parts.valid_body());
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("socket"), "{out}");
    assert!(out.contains("writable"), "{out}");
}

#[test]
fn refuses_when_another_instance_holds_the_socket() {
    let first = common::Supervisor::start();
    // Second instance, same socket path (fresh dir, same socket).
    let mut f2 = Fixture::new();
    f2.parts.socket = first.socket.clone();
    let config = f2.parts.write_config(&f2.parts.valid_body());
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("already listening"), "{out}");
    drop(first);
}

#[test]
fn refuses_private_key_as_root_key() {
    let f = Fixture::new();
    // Overwrite the root key with a *private* key.
    let kp = biscuit_auth::KeyPair::new_with_algorithm(biscuit_auth::Algorithm::Secp256r1);
    std::fs::write(&f.parts.root_key, kp.to_private_key_pem().unwrap().as_bytes()).unwrap();
    let config = f.parts.write_config(&f.parts.valid_body());
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("PRIVATE key"), "{out}");
}

#[test]
fn refuses_missing_root_key() {
    let f = Fixture::new();
    let body = f
        .parts
        .valid_body()
        .replace(&f.parts.root_key.display().to_string(), "missing.pub");
    let config = f.parts.write_config(&body);
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("root key"), "{out}");
}

#[test]
fn refuses_invalid_peer_requirement() {
    let f = Fixture::new();
    let body = f.parts.body("identifier is 12345 not a valid requirement (((");
    let config = f.parts.write_config(&body);
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("requirement"), "{out}");
}

#[test]
fn refuses_unknown_config_field() {
    let f = Fixture::new();
    let body = format!("{}extra_field = 1\n", f.parts.valid_body());
    let config = f.parts.write_config(&body);
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.contains("unknown field"), "{out}");
}

#[test]
fn refuses_corrupt_audit_chain() {
    let f = Fixture::new();
    // Build a valid log first, then corrupt a byte in the interior of the
    // first event record (not the last frame — an interior corruption is
    // always a hard refusal).
    {
        let mut sup = common::Supervisor::start_with_body(&f, &f.parts.valid_body());
        let mut client = common::Client::connect(&sup.socket);
        let _ = client.hello(&sup.token("agent:planner", &["Whoami"]));
        drop(client);
        sup.terminate_and_wait();
    }

    let bytes = std::fs::read(&f.parts.audit).unwrap();
    let split = ramen_audit::split_frames(&bytes);
    assert!(split.frames.len() >= 3, "header + opened + closed expected");
    let (s, _) = split.frames[1]; // the SessionOpened frame
    let mut corrupted = bytes.clone();
    corrupted[s + 5] ^= 0xFF; // flip a byte inside the JSON payload
    std::fs::write(&f.parts.audit, &corrupted).unwrap();

    let config = f.parts.write_config(&f.parts.valid_body());
    let (status, out) = run_to_exit(&config);
    assert!(!status.success());
    assert!(out.to_lowercase().contains("audit"), "{out}");
}

#[test]
fn resumes_after_clean_restart() {
    let f = Fixture::new();

    let mut sup = common::Supervisor::start_with_body(&f, &f.parts.valid_body());
    {
        let mut client = common::Client::connect(&sup.socket);
        client.hello(&sup.token("agent:planner", &["Whoami"]));
        client.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}));
        drop(client);
    }
    sup.terminate_and_wait();

    // Second instance reuses the same audit file: the chain must verify and
    // continue.
    common::assert_chain_valid(&f.parts.audit);
    let mut sup2 = sup.restart();
    let mut client = common::Client::connect(&sup2.socket);
    client.hello(&sup.token("agent:planner", &["Whoami"]));
    let _ = client.request(ramen_proto::Operation::Whoami(ramen_proto::WhoamiOp {}));
    drop(client);
    sup2.terminate_and_wait();
    common::assert_chain_valid(&f.parts.audit);
}
