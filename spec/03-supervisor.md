# 03 — `ramen-supervisor`

Milestone M3. Listen, accept, frame, identify the peer, complete the handshake.
**No operations.** Every well-formed request returns `Error/NotImplemented`,
and that response is audited as `Errored`.

Ending the milestone here is intentional. It produces a running system whose
only behavior is refusing to do things, which is exactly the behavior that must
be correct before anything else is added.

## 1. Startup

In order. Any failure aborts the process with a nonzero exit and a message on
stderr. There is no partial start.

1. Read configuration (§2).
2. Open the audit log. Verify the chain; recover a partial trailing frame per
   `02-audit.md` §6. Refuse to start on an interior chain failure.
3. Load the root public key (`04-guard.md` §3). **Refuse to start if the
   file parses as a private key.** Biscuit 6.x key serialization
   differentiates the two, making this check trivial. It guards against the
   one-character configuration mistake that would put minting capability in the
   privileged process: the supervisor only ever verifies.
4. Create the socket (§3).
5. Append `SessionOpened`-adjacent startup marker? **No** — do not invent a
   record kind. The `LogHeader` on a fresh log and the first real session record
   are sufficient. Resist the urge to log liveness into the audit chain;
   liveness belongs in `tracing`.
6. Accept connections.

The supervisor does not daemonize itself, does not write a pidfile, and does not
manage its own restarts. It runs in the foreground under `launchd`. Process
supervision is a solved problem owned by the platform. The LaunchAgent plist is
a deployment artifact outside this repository, but the supervisor's
fail-exit-on-audit-failure design (`00-overview.md` invariant 4) only works
if the restart is visible and does not spin: the plist must restart the
process on nonzero exit (e.g. `KeepAlive` with `SuccessfulExit = false`), and
launchd's throttle (`ThrottleInterval`, default 10s) bounds the crash loop a
permanently unwritable audit log produces to a visible tick rather than a
spin. A plist that suppresses restarts on nonzero exit makes a dead supervisor
look alive in `launchctl`.

## 2. Configuration

TOML, path from `--config`, no default search path, no environment-variable
overrides.

```toml
socket_path   = "/Users/austin/.ramen/sup.sock"
audit_path    = "/Users/austin/.ramen/audit.log"
root_key_path = "/Users/austin/.ramen/root.pub"
state_dir     = "/Users/austin/.ramen/state"

[peer]
requirement = 'identifier "com.example.planner" and anchor apple generic'
```

No env-var overrides because configuration determines the enforcement boundary,
and the environment of a privileged process is a weaker channel than a file with
known ownership and mode. Anything that can set an env var on the supervisor can
already do worse, but there is no reason to add the path.

`state_dir` holds supervisor-owned state — in v0, the `snapshots/` subdirectory
(`05-operations.md`). It is control-plane state: its entire subtree is protected
by the guard (`04-guard.md` §7), and it must be on the same filesystem as every
allowed prefix (`05-operations.md`).

`requirement` is a raw `SecRequirement` string, compiled once at startup (§4).
The production form is an identifier plus `anchor apple generic` — chained to
an Apple-issued certificate, which covers Developer ID and local development
certificates. (`anchor apple` means signed by Apple itself — essentially only
OS binaries — and is not what you want here.)

**CI form.** CI test binaries are signed **ad-hoc** (`codesign -s -`) and their
signing identifier is pinned in the test config:

```toml
requirement = 'identifier "ramen-ctl"'
```

Ad-hoc signing needs no certificate, and `SecCodeCheckValidity` against an
identifier requirement works on ad-hoc-signed binaries. So CI exercises the real
identity path — audit token, `SecCodeCopyGuestWithAttributes`, validity check —
with no Apple cert and no self-hosted runner. The pinned identifier is the
test binary's ad-hoc signing identifier, read in the build step (e.g. via
`codesign -dv`) and written into the test config.

**Why not `cdhash` pinning (M3 empirical correction).** The
requirement-language `cdhash` term only accepts 20-byte (SHA-1) hashes and does
**not** match code signed with SHA-256 — which is what every ad-hoc signature
on modern macOS uses. Verified during M3 implementation: a `cdhash` requirement
built from a SHA-256 binary's code-directory hash (truncated, SHA-1-of-SHA-256,
or the full 64-hex form) all fail `SecCodeCheckValidity` against that same
binary, and the toolchain offers no way to produce SHA-1 signatures. `identifier`
pinning is therefore the CI form. It is weaker than a content pin (any local
process can ad-hoc sign with the same identifier), which is acceptable in the
v0 single-user trust model: everything the supervisor protects is local to one
user. The socket is `0600`, and the sensitive material — the minter's
*private* key and the minted token files — is readable only by the same user.
(Note the supervisor's `root_key_path` is the *public* key: being able to read
it grants nothing, only the minter's private key can mint.) A same-user
attacker can therefore mint tokens, read existing ones, and reach the socket;
the supervisor's checks do not defend against that attacker and are not
claimed to. They exist to make cross-user and cross-process misuse of the
socket impossible, and to keep the audit log meaningful. The cdhash
(truncated SHA-256) is still extracted and recorded in the audit trail for
forensics.

There is **no development bypass flag.** An earlier draft of this spec had
`require_valid_signature = false`; it is deleted. A flag that downgrades the
consequence of a check is exactly what this design forbids, and the CI need it
was standing in for is met by the identifier requirement instead.

Refuse to start if the config file is group- or world-writable.

## 3. Socket lifecycle

- Unlink a stale socket path at startup **only after** confirming no process
  holds it: attempt `connect()` first; if it succeeds, abort with "already
  running". Blindly unlinking lets a second instance silently hijack the path.
- `bind()`, then immediately `chmod` to `0600` before `listen()`. Between `bind`
  and `chmod` the socket exists with the process umask; do not leave that
  window open by ordering these the other way.
- The containing directory must be owned by the supervisor's uid and not
  group/world writable. Check and refuse otherwise — a writable parent directory
  means the socket can be replaced regardless of its own mode.
- On `SIGTERM`/`SIGINT`: stop accepting, allow in-flight operations to complete
  with a bounded deadline (30s), write `SessionClosed` for each open session,
  **drain the audit writer queue**, flush and close the audit log, unlink the
  socket, exit 0.

Backpressure: cap concurrent connections (default 64). Beyond that, accept and
immediately close with a `Fault` (`Internal`), recorded under a dedicated
`tracing` warning only — **never** in the audit log. A connection flood must not
be allowed to fill the audit log, which is the thing that must never fail.

**Rate-limit audit writes from unauthenticated peers.** This is a real
availability concern: an attacker who can force unbounded audit appends can fill
the disk and trigger invariant 4, converting a nuisance into a full denial of
service.

Concretely: `IdentityRejected` and pre-handshake `ProtocolViolation` records are
written at most once per peer PID per 10-second window; suppressed events
increment a counter included in the next written record.

## 4. Peer identity

This is the part most likely to be implemented in a subtly wrong way. Read this
section carefully.

### Do not use `LOCAL_PEERPID` alone

The obvious implementation — `getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, ...)`,
then `SecCodeCreateWithPID`-style lookup, then `SecCodeCheckValidity` — has a
PID-reuse race. Between reading the PID and inspecting the process, the original
process can exit and its PID be reused by a different, attacker-chosen binary.
The window is small but it is a real, exploitable TOCTOU, and it is precisely
the kind of check that appears to work in every test.

### Use the audit token

macOS provides the peer's audit token, which identifies the specific process
instance and is not subject to reuse.

```
getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &audit_token, &len)
```

Then build a `SecCode` from it:

```
attrs = { kSecGuestAttributeAudit: <audit_token as CFData> }
SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code)
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement)
```

Then extract signing information with `SecCodeCopySigningInformation` for
`kSecCodeInfoIdentifier` (signing id) and `kSecCodeInfoUnique` (cdhash).

If `LOCAL_PEERTOKEN` is unavailable on the running OS version, **fail closed**.
Do not fall back to PID. A fallback path that is never exercised in testing and
is weaker than the primary path is worse than no fallback: it will be the path
taken in production the one time it matters.

`LOCAL_PEERPID` is still read, but **only** to populate `peer.pid` in the audit
record as a diagnostic. It must not feed any decision.

### Requirement string

Build a `SecRequirement` from the `requirement` string in configuration
(§2). Examples:

```
identifier "com.example.planner" and anchor apple generic   # production
identifier "ramen-ctl"                                      # CI (ad-hoc signed)
```

Compile it once at startup with `SecRequirementCreateWithString` and reuse.
Compiling per-connection is both slow and an opportunity to get the string
wrong under load. A compile failure at startup is a startup abort, not a
runtime denial.

### What this check is and is not

This establishes *which binary* is connecting. It does not establish that the
binary is trustworthy, and it cannot: an attacker who owns the machine can patch
any local binary, and a validly-signed process can be debugged, injected into,
or simply be a legitimate agent behaving badly.

The security of the system rests on **mediation of every action**, not on
identifying the caller. Peer identity narrows the population of callers and
makes the audit log meaningful. It is not a substitute for the guard, and no
guard decision may be relaxed on the basis of a good signature.

This distinction is worth a comment in the source, because the natural next
thought when peer verification is working is "we can trust this caller now,"
and that thought is the beginning of ambient authority.

**There is no token-to-identity binding in v0.** The peer requirement decides
which *binary* may connect; the token decides what a connection may do. These
are independent axes, and v0 deliberately does not join them: nothing in the
handshake checks that the token was minted *for* the connecting binary. Any
process whose binary satisfies the requirement can use any token it can read.
That is acceptable in the single-user model below — a same-user attacker can
mint its own tokens anyway — but it means "verified peer" must never be read
as "verified agent".

### Module layout

Confine all of the above to `platform::darwin`:

```rust
pub struct PeerIdentity {
    pub pid: i32,
    pub signing_id: Option<String>,
    pub cdhash: Option<String>,
    pub verified: bool,
}

#[cfg(target_os = "macos")]
pub fn identify(fd: RawFd, req: &SecRequirement) -> Result<PeerIdentity, IdentityError>;
```

Every `unsafe` block gets a comment stating the invariant that makes it sound.

## 5. Connection state machine

```
      accept
        │
        ▼
  ┌───────────┐  identity fails   ┌──────────────────┐
  │ Identify  ├──────────────────►│ audit            │
  └─────┬─────┘                   │ IdentityRejected │
        │ ok                      │ close            │
        ▼                         └──────────────────┘
  ┌───────────┐  bad Hello / token invalid
  │ Handshake ├───────────────────────────────► audit, Fault, close
  └─────┬─────┘
        │ ok → audit SessionOpened, send Welcome
        ▼
  ┌───────────┐
  │  Ready    │◄──┐  request → dispatch → response
  └─────┬─────┘   └──────────────────────────────┘
        │ EOF, fatal violation, or shutdown
        ▼
  audit SessionClosed, close
```

Model this as an explicit `enum ConnState` with a transition function, not as
control flow in an async block. The states have different permitted messages,
and an explicit machine makes "can a `Hello` arrive in `Ready`" a question the
type system helps answer rather than one that depends on reading a long
function.

**Identity is resolved before the first read.** Do not read `Hello` and then
identify — the token is attacker-supplied and should not be parsed by a peer
whose identity has not been established.

### Concurrency

One `tokio` task per connection. Within a connection, requests are dispatched
concurrently, tracked in a `HashMap<RequestId, ...>` bounded at 32 in-flight. A
33rd in-flight request gets `Error/Internal` rather than unbounded queueing.

Responses are written through a single `mpsc` channel per connection with a
dedicated writer task, so frames from concurrent handlers cannot interleave
mid-frame. This is the one concurrency bug in this design that would be
catastrophic and silent — a torn frame corrupts the stream, and the decoder
would resynchronize onto garbage. Write the test.

**Request ids are single-use for the lifetime of the connection**
(`01-protocol.md` §3). The supervisor keeps a per-connection seen-set, capped
at 65,536 entries. Any reuse of a seen id — in flight or already terminal — is
a fatal protocol violation. A connection that exhausts the cap is closed with
`Fault` (`Internal`).

## 6. Dispatch (M3 form)

```rust
async fn dispatch(ctx: &SessionCtx, req: Request) -> Response {
    // M3: guard not yet wired. Audit and refuse.
    ctx.audit
        .append(&Record::errored(&req, ErrorCode::NotImplemented))
        .await?;
    Response::error(req.id, ErrorCode::NotImplemented, "not available in v0")
}
```

In M4 this grows a guard call before the operation match. In M5+ it grows the
operation match. The audit append stays first.

## 7. Acceptance criteria (M3)

- [ ] Supervisor starts, creates the socket at `0600`, accepts a connection.
- [ ] Refuses to start if: audit chain interior-invalid; config world-writable;
      socket directory group-writable; another instance holds the socket;
      `root_key_path` parses as a private key.
- [ ] A test client satisfying the configured requirement (CI: ad-hoc signed,
      identifier pinned in the test config) connects and receives `Welcome`; audit
      shows `SessionOpened` with `verified: true`, a populated `cdhash`, and the
      `client` metadata.
- [ ] A client that does not satisfy the requirement (unsigned, or ad-hoc under
      an anchor-based requirement) is rejected; audit shows `IdentityRejected`;
      no `SessionOpened` record exists.
- [ ] A client whose identifier does not match the requirement is rejected.
- [ ] Identity resolution uses `LOCAL_PEERTOKEN`. Verify by inspection; assert
      in a test comment that `LOCAL_PEERPID` appears only in the record-building
      path. Add a CI grep asserting `LOCAL_PEERPID` does not appear in any
      conditional expression.
- [ ] Every request returns `Error/NotImplemented` and produces an `Errored`
      audit record.
- [ ] Fatal violations from `01-protocol.md` §8 — including request-id reuse —
      each close the connection and produce a `ProtocolViolation` record plus a
      best-effort `Fault`. One test per violation type.
- [ ] Two concurrent handlers writing large responses produce no torn frames —
      run 1000 interleaved responses through the writer task and verify every
      frame decodes.
- [ ] 200 connections in a flood produce at most ~1 audit record per PID per 10s
      window, with a suppression counter; connections beyond the cap receive a
      `Fault` and a `tracing` warning only, and no audit record.
- [ ] `SIGTERM` writes `SessionClosed` for every open session, drains the audit
      queue, unlinks the socket, exits 0.
- [ ] Kill with `SIGKILL` mid-session: verifier reports at most a truncation
      warning, never a chain failure.
