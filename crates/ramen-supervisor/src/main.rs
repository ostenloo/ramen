//! `ramen-supervisor` — the Ramen control-plane daemon (`03-supervisor.md`).
//!
//! Startup is strict: any failure (config, audit chain, root key, socket)
//! aborts with a non-zero exit and a message on stderr. There is no
//! daemonization; the process runs in the foreground and is meant to be
//! supervised externally.
//!
//! ```text
//! ramen-supervisor --config <path>
//! ```

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use biscuit_auth::PublicKey;
use ramen_audit::{NewRecord, PeerInfo, RecordKind, AuditLog};
use ramen_guard::{ControlPlanePaths, Guard, RootKey, StdFs};
use ramen_proto::{ErrorCode, Fault, Message};
use ramen_supervisor::conn::{to_audit_peer, ConnCtx, MAX_CONNECTIONS, serve};
use ramen_supervisor::config::load;
use ramen_supervisor::platform::IdentityError;
use ramen_supervisor::rate_limit::{Decision, RejectionLimiter};
use ramen_supervisor::rootkey::load_root_public_key;
use ramen_supervisor::socket;
use security_framework::os::macos::code_signing::SecRequirement;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

/// Bounded deadline for in-flight work during shutdown (`03-supervisor.md` §7).
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(async { run().await });
    std::process::exit(code);
}

async fn run() -> i32 {
    // `--config` is the only argument; no default search path.
    let mut args = std::env::args().skip(1);
    let (Some(flag), Some(path)) = (args.next(), args.next()) else {
        eprintln!("usage: ramen-supervisor --config <path>");
        return 1;
    };
    if flag != "--config" {
        eprintln!("unknown argument: {flag} (expected --config)");
        return 1;
    }
    let config_path = std::path::PathBuf::from(path);

    // Logging: stdout, plain, RUST_LOG-filtered.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // 1. Config.
    let config = match load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("startup failed: config: {e}");
            return 1;
        }
    };

    // 2. Audit log: open verifies the existing chain and recovers a torn
    //    tail; a corrupt log is a startup refusal.
    let audit = match AuditLog::open(&config.audit_path, VERSION) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("startup failed: audit log: {e}");
            return 1;
        }
    };

    tracing::info!(audit = %config.audit_path.display(), "audit log open");

    // 3. Root public key (refuses a private key).
    let root = match load_root_public_key(&config.root_key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("startup failed: root key: {e}");
            return 1;
        }
    };

    // 3b. Guard (`04-guard.md`): control-plane paths and the authorization
    //     engine. The supervisor's loaded root public key backs the guard's
    //     RootKey — the supervisor never holds a private key.
    let state_dir = match config.state_dir.canonicalize() {
        Ok(d) => d,
        Err(_e) => {
            // The state directory may not exist yet (first run); create it
            // and then canonicalize.
            if let Err(c) = std::fs::create_dir_all(&config.state_dir) {
                eprintln!("startup failed: state_dir: {c}");
                return 1;
            }
            match config.state_dir.canonicalize() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("startup failed: state_dir: {e}");
                    return 1;
                }
            }
        }
    };
    // The state directory holds snapshots — the pre-images of every file an
    // agent has ever overwritten. It is control-plane state, not agent data:
    // 0700, explicitly, so a default umask or a pre-existing 0755 directory
    // cannot leave pre-images world-readable on a multi-user host
    // (`05-operations.md` M6).
    if let Err(e) = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)) {
        eprintln!("startup failed: state_dir permissions (0700): {e}");
        return 1;
    }
    let control_plane = match ControlPlanePaths::new(
        &[
            config.socket_path.clone(),
            config.audit_path.clone(),
            config.root_key_path.clone(),
            config_path.clone(),
        ],
        &state_dir,
    ) {
        Ok(cp) => cp,
        Err(e) => {
            eprintln!("startup failed: control-plane paths: {e}");
            return 1;
        }
    };
    let guard = Arc::new(Guard::new(
        Box::new(PublicKeyRootKey(root)),
        control_plane,
        Box::new(StdFs),
    ));

    // 3c. `FileWrite` effect prerequisites (`05-operations.md` M6):
    //     - the snapshots directory under the state dir;
    //     - the volume check: `state_dir` must be on APFS and every
    //       configured allowed prefix must share a device with it
    //       (`clonefile` does not cross volumes) — a startup refusal,
    //       not a fallback.
    let snapshots_dir = state_dir.join("snapshots");
    if let Err(e) = std::fs::create_dir_all(&snapshots_dir) {
        eprintln!("startup failed: snapshots dir: {e}");
        return 1;
    }
    // Same guarantee as the state dir (inherited, but stated for the leaf):
    // snapshots are 0600 files inside a 0700 directory.
    if let Err(e) = std::fs::set_permissions(&snapshots_dir, std::fs::Permissions::from_mode(0o700)) {
        eprintln!("startup failed: snapshots dir permissions (0700): {e}");
        return 1;
    }
    let config_prefixes: Vec<std::path::PathBuf> = config
        .allowed_prefixes
        .iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(c) => Some(c),
            Err(_) => {
                // A configured prefix that does not exist can never match a
                // write target (the guard requires the parent to exist);
                // it is skipped rather than a startup refusal.
                tracing::warn!(prefix = %p.display(), "allowed prefix does not exist; ignoring");
                None
            }
        })
        .collect();
    if let Err(e) = ramen_supervisor::volume::check_startup_volumes(&state_dir, &config_prefixes) {
        eprintln!("startup failed: volume check: {e}");
        return 1;
    }
    tracing::info!(
        state_dir = %state_dir.display(),
        prefixes = config_prefixes.len(),
        "volume check passed (APFS, same device)"
    );

    // 4. Peer requirement, compiled once at startup.
    let requirement = match SecRequirement::from_str(&config.peer_requirement) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("startup failed: peer requirement is not a valid SecRequirement: {e}");
            return 1;
        }
    };

    // 5. Socket: directory check, live-instance probe, stale unlink,
    //    bind, chmod 0600.
    let std_listener = match socket::listen(&config.socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("startup failed: socket: {e}");
            return 1;
        }
    };
    // Tokio 1.53+ refuses to adopt a blocking fd; set non-blocking first.
    std_listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let listener = match UnixListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("startup failed: socket: {e}");
            return 1;
        }
    };
    tracing::info!(socket = %config.socket_path.display(), "listening");

    // The shutdown channel: a watch receiver in `ctx` (every connection
    // observes `changed()`), the sender kept here for the signal path.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(ConnCtx {
        audit: audit.clone(),
        root,
        guard,
        limiter: Arc::new(RejectionLimiter::new()),
        shutdown: shutdown_rx,
        config_prefixes,
        snapshots_dir,
    });

    // Accept loop; returns once a shutdown signal arrives (connections are
    // joined inside it, within the bounded shutdown deadline).
    accept_loop(listener, ctx.clone(), &requirement, shutdown_tx).await;

    // -- Shutdown sequence (03-supervisor.md §7) ----------------------------
    // Connections were signalled and joined inside the loop, within the
    // bounded deadline. Remaining steps: drain the audit, unlink the socket.
    // `ctx` is the last other reference once the loop returns, so dropping
    // it leaves exactly one strong ref and the log can be closed.
    drop(ctx);
    match Arc::try_unwrap(audit) {
        Ok(log) => match log.close() {
            Ok(()) => tracing::info!("audit log closed"),
            Err(e) => eprintln!("shutdown: audit close failed: {e}"),
        },
        Err(_arc) => {
            // A connection was abandoned at the deadline and still holds a
            // reference; the log is closed when the last reference drops
            // (the process is exiting anyway).
            tracing::warn!("audit log still referenced at shutdown; closing via Drop");
        }
    }
    socket::unlink(&config.socket_path);
    tracing::info!("shutdown complete");
    0
}

async fn accept_loop(
    listener: UnixListener,
    ctx: Arc<ConnCtx>,
    requirement: &SecRequirement,
    shutdown_tx: watch::Sender<bool>,
) {
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("startup failed: SIGTERM handler: {e}");
            std::process::exit(1);
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("startup failed: SIGINT handler: {e}");
            std::process::exit(1);
        }
    };

    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received; shutting down");
                break;
            }
            accepted = listener.accept() => match accepted {
                Ok((mut stream, _)) => {
                    // Reap finished connections so the cap counts live ones.
                    handles.retain(|h| !h.is_finished());

                    // Connection cap: accept, then immediately close with a
                    // Fault. Deliberately NOT audited (03-supervisor.md §8) —
                    // the audit must not be a DoS amplifier; a tracing
                    // warning is the whole record.
                    if handles.len() as u32 >= MAX_CONNECTIONS {
                        tracing::warn!(max = MAX_CONNECTIONS, "connection cap reached; rejecting");
                        let fault = Message::Fault(Fault::new(
                            ErrorCode::Internal,
                            "too many connections",
                        ));
                        let mut buf = Vec::new();
                        if fault.encode(&mut buf).is_ok() {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(1),
                                stream.write_all(&buf),
                            )
                            .await;
                        }
                        drop(stream);
                        continue;
                    }

                    // Identity: resolved BEFORE the first read; fail closed,
                    // no fallback to PID.
                    let fd = stream.as_raw_fd();
                    match ramen_supervisor::platform::identify(fd, requirement) {
                        Ok(peer) if peer.verified => {
                            handles.push(tokio::spawn(serve(stream, peer, ctx.clone())));
                        }
                        Ok(peer) => {
                            audit_identity_rejected(
                                &ctx,
                                Some(to_audit_peer(&peer)),
                                "requirement not met",
                            )
                            .await;
                            drop(stream);
                        }
                        Err(e) => {
                            audit_identity_rejected(&ctx, None, &no_peer_code_reason(&e)).await;
                            drop(stream);
                        }
                    }
                }
                Err(e) => {
                    // A failed accept (e.g. EMFILE) is logged; the listener
                    // is still usable.
                    tracing::warn!("accept failed: {e}");
                }
            }
        }
    }

    // Shutdown: mark the channel so every connection — current or not yet
    // waiting — observes the shutdown on its next `changed()`. Then join
    // within the bounded deadline, which starts now, at signal time.
    tracing::info!("signalling connections to close");
    let _ = shutdown_tx.send(true);
    let deadline = Instant::now() + SHUTDOWN_DEADLINE;
    for h in handles {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Deadline exhausted: abandon this task; the process exits and
            // the OS reaps it. The audit is already drained after this loop.
            drop(h);
            continue;
        }
        let _ = tokio::time::timeout(remaining, h).await;
    }
}

fn no_peer_code_reason(e: &IdentityError) -> String {
    format!("no peer code: {e}")
}

/// The guard's `RootKey` backed by the supervisor's loaded root public key.
/// Verification only (`04-guard.md` §3): the supervisor never mints.
struct PublicKeyRootKey(PublicKey);

impl RootKey for PublicKeyRootKey {
    fn public_key(&self) -> PublicKey {
        self.0
    }
}

/// Audit an identity rejection (rate-limited per peer PID;
/// `03-supervisor.md` §8).
async fn audit_identity_rejected(ctx: &Arc<ConnCtx>, peer: Option<PeerInfo>, reason: &str) {
    let Some(pid) = peer.as_ref().map(|p| p.pid as i32) else {
        // The peer could not be resolved at all (no audit token → no code).
        // There is no PID to rate-limit on; the connection cap bounds such
        // events, so write unconditionally.
        let record = NewRecord {
            kind: RecordKind::IdentityRejected,
            session: None,
            identity: None,
            peer: None,
            request_id: None,
            op_type: None,
            reversibility: None,
            detail: serde_json::json!({ "reason": reason }),
            client: None,
        };
        if let Err(e) = ctx.audit.append(&record).await {
            tracing::error!("identity-rejected audit failed: {e}");
        }
        return;
    };

    let decision = ctx.limiter.record(pid);
    if !matches!(decision, Decision::Write { .. }) {
        return;
    }
    let mut detail = serde_json::json!({ "reason": reason });
    if let Decision::Write { suppressed } = decision {
        if suppressed > 0 {
            detail["suppressed"] = serde_json::json!(suppressed);
        }
    }
    let record = NewRecord {
        kind: RecordKind::IdentityRejected,
        session: None,
        identity: None,
        peer,
        request_id: None,
        op_type: None,
        reversibility: None,
        detail,
        client: None,
    };
    if let Err(e) = ctx.audit.append(&record).await {
        tracing::error!("identity-rejected audit failed: {e}");
    }
}
