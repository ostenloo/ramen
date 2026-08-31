//! Connection handling: the state machine, handshake, dispatch, and the
//! per-connection response writer (`03-supervisor.md` §5–§8,
//! `01-protocol.md` §5/§8).
//!
//! State machine:
//!
//! ```text
//! Identify  --ok-->  Handshake --ok-->  Ready  --EOF/violation-->  Closed
//!    |                    |               |
//!    +--fail--> audit IdentityRejected, close
//!    +--fail--> audit ProtocolViolation (rate-limited), best-effort Fault, close
//! ```
//!
//! Identity resolution itself happens in the accept loop (`main`), **before
//! the first read**; this module only sees verified peers.
//!
//! Responses on a connection are written by a single dedicated task fed by
//! an mpsc channel, so frames from concurrent requests never interleave.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use biscuit_auth::PublicKey;
use ramen_audit::{AuditError, AuditLog, ClientMeta, NewRecord, PeerInfo, RecordKind};
use ramen_guard::{AuthzRequest, Decision, Guard};
use ramen_proto::codec::Decoder;
use ramen_proto::messages::{Denial, Welcome, WelcomeTag};
use ramen_proto::{
    DenialCode, ErrorCode, Fault, FileWriteOp, FileWriteResult, Message, Operation, OpResult,
    PROTOCOL_VERSION, Request, RequestId, Response, Reversibility, SessionId, WhoamiOp,
    WhoamiResult, WriteMode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, watch};

use crate::filewrite;
use crate::platform::PeerIdentity;
use crate::rate_limit::{Decision as RateDecision, RejectionLimiter};

/// Maximum simultaneously open connections (`03-supervisor.md` §8).
pub const MAX_CONNECTIONS: u32 = 64;
/// Maximum in-flight requests per connection.
pub const MAX_IN_FLIGHT: usize = 32;
/// Maximum request ids remembered per connection; exhaustion is fatal
/// (`Fault(Internal)`).
pub const MAX_SEEN_REQUEST_IDS: usize = 65_536;

/// State shared by all connections (and the accept loop).
pub struct ConnCtx {
    pub audit: Arc<AuditLog>,
    /// Root **public** key — the supervisor only ever sees this.
    pub root: PublicKey,
    /// The guard: Biscuit authorization for every request (`04-guard.md`).
    pub guard: Arc<Guard>,
    pub limiter: Arc<RejectionLimiter>,
    /// Set to `true` once at shutdown; every connection then stops reading
    /// (a watch receiver: late subscribers still see the change) and audits
    /// `SessionClosed` (if a session was opened).
    pub shutdown: watch::Receiver<bool>,
    /// Supervisor-level bound on `FileWrite` targets: canonicalized
    /// `allowed_prefixes` from the config (`05-operations.md` M6). An empty
    /// list means no `FileWrite` can ever succeed (fail closed).
    pub config_prefixes: Vec<PathBuf>,
    /// Where pre-write snapshots live: `<state_dir>/snapshots`.
    pub snapshots_dir: PathBuf,
}

/// The audit-facing form of a verified peer identity.
pub fn to_audit_peer(peer: &PeerIdentity) -> PeerInfo {
    PeerInfo {
        pid: peer.pid as u32,
        signing_id: peer.signing_id.clone(),
        cdhash: peer.cdhash.clone(),
        verified: peer.verified,
    }
}

/// True when `path` equals `prefix` or lies beneath it — compared
/// component-wise, so `/a/bb` is **not** within `/a/b`.
fn starts_within(path: &Path, prefix: &Path) -> bool {
    let path_comps = path.components();
    let prefix_comps = prefix.components();
    for (a, b) in path_comps.clone().zip(prefix_comps.clone()) {
        if a != b {
            return false;
        }
    }
    prefix_comps.count() <= path_comps.clone().count()
}

// ---------------------------------------------------------------------------
// Audit append (fail-exit on failure)
// ---------------------------------------------------------------------------

static AUDIT_APPENDS: AtomicU64 = AtomicU64::new(0);

/// Append an audit record; on failure **terminate the process** with
/// `EXIT_AUDIT_UNAVAILABLE` (invariant 4, `00-overview.md`). The audit
/// writer is process-wide: once it is dead, invariant 2 (audit precedes
/// effect) can no longer hold for any connection, and continuing would be
/// exactly the reduced-enforcement mode the invariant forbids. A v0
/// supervisor therefore never sends `Error/AuditUnavailable` — the client
/// sees a closed connection instead (`01-protocol.md` §6).
///
/// Test hook: `RAMEN_TEST_AUDIT_FAIL_AFTER=N` makes the Nth append
/// (process-wide count) fail so tests can exercise this path.
async fn audit_append(audit: &AuditLog, record: &NewRecord) -> u64 {
    let n = AUDIT_APPENDS.fetch_add(1, Ordering::Relaxed) + 1;
    let fail_at = std::env::var("RAMEN_TEST_AUDIT_FAIL_AFTER")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let res = if fail_at == Some(n) {
        tracing::error!("test hook: simulating audit writer failure on append {n}");
        Err(AuditError::Closed)
    } else {
        audit.append(record).await
    };
    match res {
        Ok(seq) => seq,
        Err(e) => {
            tracing::error!(
                "audit append failed: {e} — invariant 4: the supervisor cannot continue without a working audit log; exiting"
            );
            std::process::exit(crate::EXIT_AUDIT_UNAVAILABLE);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

struct Connection {
    reader: OwnedReadHalf,
    decoder: Decoder,
    tx: mpsc::Sender<Message>,
    ctx: Arc<ConnCtx>,
    peer: PeerInfo,
    session: Option<SessionId>,
    identity: Option<String>,
    /// The token's base64 wire form, held for the guard (`04-guard.md` §4,
    /// §9): the guard re-verifies the root from the wire form itself.
    token: Option<String>,
    /// Every request id seen on this connection, in-flight or terminal
    /// (single-use semantics, `01-protocol.md` §7).
    seen: HashSet<RequestId>,
    /// Requests dispatched but not yet answered (writer-queued).
    in_flight: HashSet<RequestId>,
    /// Completed dispatches awaiting reaping from `in_flight`.
    pending: VecDeque<(RequestId, oneshot::Receiver<()>)>,
}

/// One authorized operation's effect path: the request plus everything
/// every audit record on the path must carry (`02-audit.md`
/// invariants 3, 4, 7). The per-operation payload is the only thing
/// that varies between effect functions.
struct Effect {
    ctx: Arc<ConnCtx>,
    req: Request,
    identity: Option<String>,
    session: SessionId,
    peer: Option<PeerInfo>,
    op_type: String,
    reversibility: Reversibility,
}

/// Why a connection is closing. Drives the final `SessionClosed` detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    /// The peer closed the connection cleanly.
    Eof,
    /// A fatal protocol violation (already audited + faulted).
    Violation,
    /// Supervisor shutdown.
    Shutdown,
    /// Cap exhaustion / audit failure / failed `Welcome` write.
    Internal,
}

impl CloseReason {
    fn audit_string(self) -> &'static str {
        match self {
            CloseReason::Eof => "eof",
            CloseReason::Violation => "violation",
            CloseReason::Shutdown => "shutdown",
            CloseReason::Internal => "internal",
        }
    }
}

/// Handle one client connection. `peer` was resolved and verified by the
/// accept loop before the first read.
pub async fn serve(stream: UnixStream, peer: PeerIdentity, ctx: Arc<ConnCtx>) {
    let (reader, writer) = stream.into_split();
    let (tx, rx) = mpsc::channel(256);
    let writer_task = tokio::spawn(writer_task(writer, rx));

    let mut conn = Connection {
        reader,
        decoder: Decoder::new(),
        tx,
        ctx,
        peer: to_audit_peer(&peer),
        session: None,
        identity: None,
        token: None,
        seen: HashSet::new(),
        in_flight: HashSet::new(),
        pending: VecDeque::new(),
    };

    let reason = conn.run().await;

    // Stop taking responses; the writer drains what is queued, then exits.
    drop(conn.tx);
    let _ = writer_task.await;

    tracing::debug!(
        session = ?conn.session,
        identity = ?conn.identity,
        ?reason,
        "connection closed"
    );
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

impl Connection {
    async fn run(&mut self) -> CloseReason {
        let reason = match self.handshake().await {
            Ok(()) => self.ready_loop().await,
            Err(reason) => reason,
        };

        if self.session.is_some() {
            self.audit_session_closed(reason).await;
        }
        reason
    }

    /// Handshake: the first frame must be a valid `Hello` with a verifiable
    /// token; on success, open the session (audit + `Welcome`).
    async fn handshake(&mut self) -> Result<(), CloseReason> {
        let first = match self.read_message().await {
            Frame::Message(m) => m,
            Frame::Eof => return Err(CloseReason::Eof),
            Frame::Protocol(e) => {
                return Err(
                    self.violation(&format!("framing: {e}"), ErrorCode::MalformedRequest).await,
                )
            }
        };

        let Message::Hello(hello) = first else {
            // Any other first message (Request/Response/Fault/Welcome) is
            // fatal: the handshake is exactly one Hello.
            return Err(
                self.violation("first message is not Hello", ErrorCode::MalformedRequest).await,
            );
        };

        if hello.v != PROTOCOL_VERSION {
            return Err(
                self.violation(
                    &format!("version mismatch: got {}, expected {PROTOCOL_VERSION}", hello.v),
                    ErrorCode::VersionMismatch,
                )
                .await,
            );
        }

        let token_b64 = hello.token;
        let identity = match crate::token::verify_token(&token_b64, &self.ctx.root) {
            Ok(i) => i,
            Err(e) => {
                return Err(
                    self.violation(&format!("handshake token: {e}"), ErrorCode::MalformedRequest)
                        .await,
                )
            }
        };

        // Open the session: audit first — there is no point serving an
        // unrecorded session, so an audit failure closes the connection.
        let session = SessionId::new();
        let (client, truncated) = hello.client.capped();
        let record = NewRecord {
            kind: RecordKind::SessionOpened,
            session: Some(session),
            identity: Some(identity.clone()),
            peer: Some(self.peer.clone()),
            request_id: None,
            op_type: None,
            reversibility: None,
            detail: serde_json::json!({}),
            client: Some(ClientMeta {
                name: client.name,
                version: client.version,
                truncated,
            }),
        };
        audit_append(&self.ctx.audit, &record).await;

        let welcome = Message::Welcome(Welcome {
            v: PROTOCOL_VERSION,
            kind: WelcomeTag::Welcome,
            session,
            identity: identity.clone(),
            // Best-effort, advisory summary (`04-guard.md` §3): never
            // affects a decision.
            capabilities: self.ctx.guard.describe_capabilities(&token_b64),
        });
        if self.tx.try_send(welcome).is_err() {
            // The client is gone before the Welcome landed. The session was
            // audited opened, so it is closed now.
            tracing::debug!("welcome could not be queued");
            self.session = Some(session);
            self.identity = Some(identity);
            self.token = Some(token_b64);
            return Err(CloseReason::Internal);
        }

        self.session = Some(session);
        self.identity = Some(identity);
        self.token = Some(token_b64);
        Ok(())
    }

    /// Ready: process requests until EOF, violation, or shutdown.
    async fn ready_loop(&mut self) -> CloseReason {
        loop {
            // Clone the receiver so `changed()` borrows a local, not `self`
            // (the read future below holds `&mut self`).
            let mut shutdown = self.ctx.shutdown.clone();
            let frame = tokio::select! {
                f = self.read_message() => f,
                _ = shutdown.changed() => return CloseReason::Shutdown,
            };

            match frame {
                Frame::Eof => return CloseReason::Eof,
                Frame::Protocol(e) => {
                    return self
                        .violation(&format!("framing: {e}"), ErrorCode::MalformedRequest)
                        .await
                }
                Frame::Message(msg) => match msg {
                    Message::Hello(_) => {
                        return self
                            .violation("Hello after handshake", ErrorCode::MalformedRequest)
                            .await
                    }
                    Message::Welcome(_) | Message::Response(_) | Message::Fault(_) => {
                        return self
                            .violation(
                                "unexpected message in Ready",
                                ErrorCode::MalformedRequest,
                            )
                            .await
                    }
                    Message::Request(req) => {
                        if req.v != PROTOCOL_VERSION {
                            // A request carries an id, so the client is told
                            // about the mismatch with an `Error` response for
                            // that id — not a `Fault` — before the connection
                            // is closed (`01-protocol.md` §4).
                            return self
                                .request_version_mismatch(
                                    &req,
                                    &format!(
                                        "version mismatch: got {}, expected {PROTOCOL_VERSION}",
                                        req.v
                                    ),
                                )
                                .await;
                        }
                        if self.seen.contains(&req.id) {
                            return self
                                .violation("request id reuse", ErrorCode::MalformedRequest)
                                .await;
                        }
                        if self.seen.len() >= MAX_SEEN_REQUEST_IDS {
                            return self
                                .fault(
                                    ErrorCode::Internal,
                                    "request id capacity exhausted",
                                    "seen-set cap exhausted",
                                )
                                .await;
                        }
                        self.seen.insert(req.id);

                        // Reap now, not just at the top of the loop: the read
                        // above may have blocked long enough for in-flight
                        // dispatches to finish, and the cap check must see a
                        // current count.
                        self.reap_pending();

                        if self.in_flight.len() >= MAX_IN_FLIGHT {
                            // Non-fatal: the connection continues.
                            self.respond_error(
                                req.id,
                                ErrorCode::Internal,
                                "too many in-flight requests",
                            )
                            .await;
                            continue;
                        }

                        self.in_flight.insert(req.id);
                        self.dispatch(req).await;
                    }
                },
            }
        }
    }

    /// Dispatch (`03-supervisor.md` §6, `04-guard.md` §8–§10, M5): guard
    /// decision, audited on both paths, then the effect.
    ///
    /// - `Deny` → audit `Denied` (detail: the denial code only — no request
    ///   content), respond `Denied` with the matching `audit_seq`.
    /// - `Allow` → audit `Authorized` **before the effect** (invariant in
    ///   `04-guard.md` §10), then run the effect and audit its outcome:
    ///   - `Whoami` (M5): no side effect; the response is the guard's
    ///     *live* view of the token (recomputed, not the cached `Welcome`
    ///     summary), audited `Executed` (`05-operations.md` M5).
    ///   - `FileWrite` (M6): pre-effect validations, audited
    ///     `Authorized` with the snapshot path and content hash, the
    ///     `fclonefileat(2)` snapshot + atomic write, then `Executed` or
    ///     `ExecutionFailed` (`05-operations.md` M6).
    /// - A decision that cannot be audited is never delivered: a dead audit
    ///   writer exits the process (`EXIT_AUDIT_UNAVAILABLE`) — invariant 4.
    async fn dispatch(&mut self, req: Request) {
        let decision = match self.token.as_deref() {
            Some(token_b64) => self.ctx.guard.authorize(AuthzRequest {
                token: token_b64,
                op: &req.op,
                now: SystemTime::now(),
            }),
            None => {
                // Dispatch only runs after a successful handshake; the
                // token is always present here.
                unreachable!("dispatch without a handshake token")
            }
        };

        let op_type = req.op.type_name().to_string();
        let reversibility = req.op.reversibility();
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        let session = self.session;
        let identity = self.identity.clone();
        let peer = Some(self.peer.clone());
        let token = self.token.clone();

        let (done_tx, done_rx) = oneshot::channel();
        let req_id = req.id;
        tokio::spawn(async move {
            let resp = match decision {
                Decision::Deny { code, reason } => {
                    let record = NewRecord {
                        kind: RecordKind::Denied,
                        session,
                        identity,
                        peer,
                        request_id: Some(req.id),
                        op_type: Some(op_type),
                        reversibility: Some(reversibility),
                        detail: serde_json::json!({ "code": code.as_str() }),
                        client: None,
                    };
                    let audit_seq = audit_append(&ctx.audit, &record).await;
                    Response::denied(
                        req.id,
                        Denial { code, reason, audit_seq },
                    )
                }
                Decision::Allow => {
                    // The decision is Allow. Each operation's effect path
                    // audits `Authorized` before the effect (invariant,
                    // `04-guard.md` §10 / `02-audit.md` invariant 4) and
                    // ends with a terminal record (`Executed` or
                    // `ExecutionFailed`).
                    let session_id = session
                        .expect("dispatch runs inside a session");
                    let effect = Effect {
                        ctx,
                        req,
                        identity,
                        session: session_id,
                        peer,
                        op_type,
                        reversibility,
                    };
                    match &effect.req.op {
                        Operation::Whoami(WhoamiOp {}) => {
                            // Dispatch only runs after a successful
                            // handshake, so the token is present.
                            let token = token
                                .clone()
                                .expect("dispatch runs after a successful handshake");
                            Self::whoami_effect(&effect, &token).await
                        }
                        Operation::FileWrite(fw) => {
                            // The `FileWrite` effect (`05-operations.md`
                            // M6).
                            Self::filewrite_effect(&effect, fw).await
                        }
                    }
                }
            };
            let _ = tx.send(Message::Response(resp)).await;
            let _ = done_tx.send(());
        });
        self.pending.push_back((req_id, done_rx));
    }

    /// `Whoami` effect path (M5): audit `Authorized`, compute the guard's
    /// *live* view of the token (recomputed now — not the cached `Welcome`
    /// summary; `05-operations.md` M5), audit `Executed`, respond.
    ///
    /// No side effect. It reports only the caller's own token — nothing
    /// about the supervisor's configuration.
    async fn whoami_effect(effect: &Effect, token: &str) -> Response {
        let record = NewRecord {
            kind: RecordKind::Authorized,
            session: Some(effect.session),
            identity: effect.identity.clone(),
            peer: effect.peer.clone(),
            request_id: Some(effect.req.id),
            op_type: Some(effect.op_type.clone()),
            reversibility: Some(effect.reversibility),
            detail: serde_json::json!({}),
            client: None,
        };
        // The decision is delivered only if it can be audited; a dead
        // writer exits the process instead (invariant 4).
        audit_append(&effect.ctx.audit, &record).await;
        let result = WhoamiResult {
            identity: effect
                .identity
                .clone()
                .expect("dispatch runs inside a session"),
            session: effect.session,
            capabilities: effect.ctx.guard.describe_capabilities(token),
            token_expires_at: effect.ctx.guard.token_expires_at(token),
        };
        // `Executed`: the (empty) effect completed. Non-mutating operations
        // get the same Authorized→Executed pair as mutating ones, so the
        // verifier's invariant 7 is uniform (`05-operations.md` M5,
        // `02-audit.md` §8).
        let record = NewRecord {
            kind: RecordKind::Executed,
            session: Some(effect.session),
            identity: effect.identity.clone(),
            peer: effect.peer.clone(),
            request_id: Some(effect.req.id),
            op_type: Some(effect.op_type.clone()),
            reversibility: Some(effect.reversibility),
            detail: serde_json::json!({}),
            client: None,
        };
        let resp = Response::ok(effect.req.id, OpResult::Whoami(result));
        audit_append(&effect.ctx.audit, &record).await;
        resp
    }

    /// `FileWrite` effect path (`05-operations.md` M6): pre-effect
    /// validations, the `Authorized` record, the write, and the terminal
    /// record.
    ///
    /// Order (load-bearing):
    /// 1. base64 decode + 256 KiB cap — a failure must happen *before* the
    ///    `Authorized` record (`Errored`/`MalformedRequest`).
    /// 2. Pin the parent directory (`fsat::pin_parent`): resolved exactly
    ///    once, the opened fd verified to be that directory by device +
    ///    inode. Every syscall of the effect then runs `*at`-relative to
    ///    the pin, so a path-component swap timed anywhere after the pin
    ///    cannot steer the write (the guard checked the path at authorize
    ///    time; the pin closes the window between authorization and effect
    ///    and yields the canonical string for the response and the audit).
    /// 3. Supervisor-level bound: the target must fall within a configured
    ///    `allowed_prefixes` entry — checked against the *pinned*
    ///    resolution, i.e. the directory the effect actually writes.
    ///    A miss is `Denied`/`ConstraintViolated` with **no** `Authorized`
    ///    record (the decision boundary refused).
    /// 4. `Authorized` `{mode, content_sha256, snapshot_path}` — durable
    ///    before any effect, including the snapshot (invariant 4).
    /// 5. The effect (`filewrite::execute_pinned`), then `Executed` or
    ///    `ExecutionFailed` (invariant 7: every `Authorized` gets a
    ///    terminal record).
    async fn filewrite_effect(effect: &Effect, fw: &FileWriteOp) -> Response {
        // (1) Decode + cap, before the Authorized record.
        let content = match base64::engine::general_purpose::STANDARD
            .decode(fw.content_b64.as_bytes())
        {
            Ok(c) if c.len() <= filewrite::MAX_CONTENT_BYTES => c,
            _ => {
                let record = NewRecord {
                    kind: RecordKind::Errored,
                    session: Some(effect.session),
                    identity: effect.identity.clone(),
                    peer: effect.peer.clone(),
                    request_id: Some(effect.req.id),
                    op_type: Some(effect.op_type.clone()),
                    reversibility: Some(effect.reversibility),
                    detail: serde_json::json!({ "code": "MalformedRequest" }),
                    client: None,
                };
                audit_append(&effect.ctx.audit, &record).await;
                return Response::error(
                    effect.req.id,
                    ErrorCode::MalformedRequest,
                    "content_b64 is invalid base64 or exceeds the 256 KiB content cap",
                );
            }
        };

        // (2) Pin the parent directory (`05-operations.md` M6 step 2).
        // Without this, each effect syscall (snapshot, temp open, rename)
        // would re-resolve the path string independently — every
        // re-resolution is a window in which an agent with write access to
        // an intermediate directory can swap a path component and steer the
        // write away from the checked directory, including outside the
        // configured prefixes of step (3). The pin makes the bound hold
        // against the directory that is actually written.
        let target_path = std::path::Path::new(&fw.path);
        let pinned = match crate::fsat::pin_parent(target_path) {
            Ok(p) => p,
            Err(e) => {
                // The target's parent disappeared (or was swapped) between
                // authorization and effect. The decision was made and is
                // audited `Authorized`; the effect failed.
                return Self::authorized_then_execution_failed(
                    effect,
                    &filewrite::authorized_detail(fw, &content, None),
                    &e.to_string(),
                )
                .await;
            }
        };
        let canon = &pinned.canon_target;

        // (3) Supervisor-level bound: the target must fall within a
        // configured allowed prefix. (The token's `allowed_prefix` facts
        // are the capability grant; this is the outer bound the supervisor
        // itself enforces, `05-operations.md` M6.)
        if !effect
            .ctx
            .config_prefixes
            .iter()
            .any(|p| starts_within(canon, p))
        {
            let record = NewRecord {
                kind: RecordKind::Denied,
                session: Some(effect.session),
                identity: effect.identity.clone(),
                peer: effect.peer.clone(),
                request_id: Some(effect.req.id),
                op_type: Some(effect.op_type.clone()),
                reversibility: Some(effect.reversibility),
                detail: serde_json::json!({ "code": "ConstraintViolated" }),
                client: None,
            };
            let audit_seq = audit_append(&effect.ctx.audit, &record).await;
            return Response::denied(
                effect.req.id,
                Denial {
                    code: DenialCode::ConstraintViolated,
                    reason: "target path is outside the supervisor's configured allowed prefixes".into(),
                    audit_seq,
                },
            );
        }

        // (4) Authorized — durable before any effect, including the
        // snapshot. `snapshot_path` is deterministic, so it is known before
        // the snapshot exists (`05-operations.md` M6 step 4).
        let snapshot_name =
            filewrite::snapshot_handle_name(canon, effect.session, effect.req.id);
        let snapshot_path = (fw.mode == WriteMode::Overwrite)
            .then(|| effect.ctx.snapshots_dir.join(&snapshot_name));
        let detail = filewrite::authorized_detail(fw, &content, snapshot_path.as_deref());
        let record = NewRecord {
            kind: RecordKind::Authorized,
            session: Some(effect.session),
            identity: effect.identity.clone(),
            peer: effect.peer.clone(),
            request_id: Some(effect.req.id),
            op_type: Some(effect.op_type.clone()),
            reversibility: Some(effect.reversibility),
            detail,
            client: None,
        };
        audit_append(&effect.ctx.audit, &record).await;

        // Test-only hook: pause after the `Authorized` record is durable but
        // before the effect runs. The crash-window test (SIGKILL between
        // authorization and write, `02-audit.md` §8) relies on this.
        if let Some(v) = std::env::var_os("RAMEN_TEST_PAUSE_AFTER_AUTHORIZED") {
            // Test hook: pause (seconds) between the durable `Authorized`
            // record and the effect. Unparseable values default to 60s.
            let secs = v.to_string_lossy().parse::<u64>().unwrap_or(60);
            tracing::info!("test hook: pausing {secs}s after Authorized for FileWrite {}", effect.req.id);
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        }

        // (5) The effect, then the terminal record. Every syscall is
        // `*at`-relative to `pinned`.
        match filewrite::execute_pinned(
            &pinned,
            &content,
            fw.mode,
            effect.session,
            effect.req.id,
            &effect.ctx.snapshots_dir,
        ) {
            Ok(outcome) => {
                let record = NewRecord {
                    kind: RecordKind::Executed,
                    session: Some(effect.session),
                    identity: effect.identity.clone(),
                    peer: effect.peer.clone(),
                    request_id: Some(effect.req.id),
                    op_type: Some(effect.op_type.clone()),
                    reversibility: Some(effect.reversibility),
                    detail: serde_json::json!({
                        "bytes_written": outcome.bytes_written,
                        "restore": outcome.restore,
                    }),
                    client: None,
                };
                let resp = Response::ok(
                    effect.req.id,
                    OpResult::FileWrite(FileWriteResult {
                        path: outcome.canonical,
                        bytes_written: outcome.bytes_written,
                        content_sha256: outcome.content_sha256,
                        restore: outcome.restore,
                    }),
                );
                audit_append(&effect.ctx.audit, &record).await;
                resp
            }
            Err(e) => {
                let record = NewRecord {
                    kind: RecordKind::ExecutionFailed,
                    session: Some(effect.session),
                    identity: effect.identity.clone(),
                    peer: effect.peer.clone(),
                    request_id: Some(effect.req.id),
                    op_type: Some(effect.op_type.clone()),
                    reversibility: Some(effect.reversibility),
                    detail: serde_json::json!({ "error": e.to_string() }),
                    client: None,
                };
                let message = e.to_string();
                let resp = Response::error(effect.req.id, ErrorCode::ExecutionFailed, &message);
                audit_append(&effect.ctx.audit, &record).await;
                resp
            }
        }
    }

    /// The canonicalize-failure tail of `filewrite_effect`: the decision was
    /// made (so it is audited `Authorized`), the effect cannot run
    /// (`ExecutionFailed`).
    async fn authorized_then_execution_failed(
        effect: &Effect,
        detail: &serde_json::Value,
        error: &str,
    ) -> Response {
        let record = NewRecord {
            kind: RecordKind::Authorized,
            session: Some(effect.session),
            identity: effect.identity.clone(),
            peer: effect.peer.clone(),
            request_id: Some(effect.req.id),
            op_type: Some(effect.op_type.clone()),
            reversibility: Some(effect.reversibility),
            detail: detail.clone(),
            client: None,
        };
        audit_append(&effect.ctx.audit, &record).await;
        let record = NewRecord {
            kind: RecordKind::ExecutionFailed,
            session: Some(effect.session),
            identity: effect.identity.clone(),
            peer: effect.peer.clone(),
            request_id: Some(effect.req.id),
            op_type: Some(effect.op_type.clone()),
            reversibility: Some(effect.reversibility),
            detail: serde_json::json!({ "error": error }),
            client: None,
        };
        let resp = Response::error(effect.req.id, ErrorCode::ExecutionFailed, error);
        audit_append(&effect.ctx.audit, &record).await;
        resp
    }

    fn reap_pending(&mut self) {
        while let Some((id, rx)) = self.pending.front_mut() {
            match rx.try_recv() {
                Ok(()) => {
                    self.in_flight.remove(id);
                    self.pending.pop_front();
                }
                Err(_) => {
                    // Not ready yet: the dispatch task holds the sender until
                    // it finishes, and we pop on the first `Ok`, so a
                    // completed channel is always reaped in order. Stop at the
                    // first incomplete entry.
                    break;
                }
            }
        }
    }

    async fn respond_error(&mut self, id: RequestId, code: ErrorCode, message: &str) {
        let resp = Response::error(id, code, message);
        let _ = self.tx.send(Message::Response(resp)).await;
    }

    // -- helpers ------------------------------------------------------------

    /// Read one complete, decoded message from the stream.
    async fn read_message(&mut self) -> Frame {
        let mut chunk = vec![0u8; 8192];
        let mut shutdown = self.ctx.shutdown.clone();
        loop {
            if let Some(frame) = self.decoder.next_frame().unwrap_or(None) {
                match Message::decode(&frame) {
                    Ok(msg) => return Frame::Message(msg),
                    Err(e) => return Frame::Protocol(e.to_string()),
                }
            }
            let n = tokio::select! {
                r = self.reader.read(&mut chunk) => match r {
                    Ok(n) => n,
                    Err(e) => {
                        // A read error (not EOF) is treated as fatal: once the
                        // stream is broken it is untrusted.
                        tracing::debug!("read error: {e}");
                        return Frame::Protocol(format!("stream: {e}"));
                    }
                },
                _ = shutdown.changed() => return Frame::Eof,
            };
            if n == 0 {
                return Frame::Eof;
            }
            if let Err(e) = self.decoder.feed(&chunk[..n]) {
                return Frame::Protocol(e.to_string());
            }
        }
    }

    /// A fatal protocol violation: audit (rate-limited pre-handshake),
    /// best-effort `Fault`, close. Returns the close reason.
    async fn violation(&mut self, reason: &str, code: ErrorCode) -> CloseReason {
        let session_open = self.session.is_some();

        if session_open {
            let record = NewRecord {
                kind: RecordKind::ProtocolViolation,
                session: self.session,
                identity: self.identity.clone(),
                peer: Some(self.peer.clone()),
                request_id: None,
                op_type: None,
                reversibility: None,
                detail: serde_json::json!({ "reason": reason }),
                client: None,
            };
            audit_append(&self.ctx.audit, &record).await;
        } else {
            // Pre-handshake: rate-limited per peer PID.
            let decision = self.ctx.limiter.record(self.peer.pid as i32);
            if matches!(decision, RateDecision::Write { .. }) {
                let mut detail = serde_json::json!({ "reason": reason });
                if let RateDecision::Write { suppressed } = decision {
                    if suppressed > 0 {
                        detail["suppressed"] = serde_json::json!(suppressed);
                    }
                }
                let record = NewRecord {
                    kind: RecordKind::ProtocolViolation,
                    session: None,
                    identity: None,
                    peer: Some(self.peer.clone()),
                    request_id: None,
                    op_type: None,
                    reversibility: None,
                    detail,
                    client: None,
                };
                audit_append(&self.ctx.audit, &record).await;
            }
        }

        let fault = Fault::new(code, format!("protocol violation: {reason}"));
        let _ = self.tx.try_send(Message::Fault(fault));
        CloseReason::Violation
    }

    /// Post-handshake `v` mismatch on a request: audit as
    /// `ProtocolViolation`, answer the request with
    /// `Error/VersionMismatch` (it has an id, so `Error` can name it —
    /// `01-protocol.md` §4), then close.
    async fn request_version_mismatch(&mut self, req: &Request, reason: &str) -> CloseReason {
        let record = NewRecord {
            kind: RecordKind::ProtocolViolation,
            session: self.session,
            identity: self.identity.clone(),
            peer: Some(self.peer.clone()),
            request_id: Some(req.id),
            op_type: None,
            reversibility: None,
            detail: serde_json::json!({ "reason": reason }),
            client: None,
        };
        audit_append(&self.ctx.audit, &record).await;
        let response = Response::error(req.id, ErrorCode::VersionMismatch, reason);
        let _ = self.tx.try_send(Message::Response(response));
        CloseReason::Violation
    }

    /// Best-effort `Fault` for a non-violation close (cap exhaustion, audit
    /// failure). Post-handshake this is audited as `ProtocolViolation`;
    /// pre-handshake it is counted through the same per-PID limiter as
    /// violations so a broken audit cannot be a DoS amplifier.
    async fn fault(&mut self, code: ErrorCode, message: &str, audit_reason: &str) -> CloseReason {
        let session_open = self.session.is_some();
        if session_open {
            let record = NewRecord {
                kind: RecordKind::ProtocolViolation,
                session: self.session,
                identity: self.identity.clone(),
                peer: Some(self.peer.clone()),
                request_id: None,
                op_type: None,
                reversibility: None,
                detail: serde_json::json!({ "reason": audit_reason }),
                client: None,
            };
            audit_append(&self.ctx.audit, &record).await;
        } else {
            let _ = self.ctx.limiter.record(self.peer.pid as i32);
        }

        let fault = Fault::new(code, message);
        let _ = self.tx.try_send(Message::Fault(fault));
        CloseReason::Internal
    }

    async fn audit_session_closed(&mut self, reason: CloseReason) {
        let record = NewRecord {
            kind: RecordKind::SessionClosed,
            session: self.session,
            identity: self.identity.clone(),
            peer: Some(self.peer.clone()),
            request_id: None,
            op_type: None,
            reversibility: None,
            detail: serde_json::json!({ "reason": reason.audit_string() }),
            client: None,
        };
        audit_append(&self.ctx.audit, &record).await;
    }
}

/// The result of one read+decode cycle.
enum Frame {
    Message(Message),
    Eof,
    /// A framing or decode failure (codec or message shape).
    Protocol(String),
}

// ---------------------------------------------------------------------------
// The response writer
// ---------------------------------------------------------------------------

/// The single writer for one connection: reads `Message`s off `rx` and writes
/// them to the stream in order. Frames from concurrent requests therefore
/// never interleave (`03-supervisor.md` §8).
async fn writer_task(mut writer: OwnedWriteHalf, mut rx: mpsc::Receiver<Message>) {
    let mut buf = Vec::new();
    while let Some(msg) = rx.recv().await {
        buf.clear();
        if let Err(e) = msg.encode(&mut buf) {
            // Cannot encode a message we constructed ourselves; treat as
            // fatal.
            tracing::error!("encode failed: {e}");
            break;
        }
        if writer.write_all(&buf).await.is_err() {
            // The peer is gone; nothing more can be delivered.
            break;
        }
    }
    let _ = writer.shutdown().await;
}
