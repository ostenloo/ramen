# Ramen — Implementation Specification (v0 core)

## What this is

Ramen is a supervisor-based control plane that mediates operations performed by
software agents. Agents do not act directly. They submit operation requests to a
privileged supervisor process over a Unix domain socket. The supervisor
authenticates the caller, authorizes the specific operation against a
capability token, records the decision in an append-only audit log, and only
then performs the operation on the agent's behalf.

This spec set describes **v0 core**: the vertical slice from wire protocol
through authorization, audit, and two concrete operations, plus a CLI client.

## Documents

| File | Scope |
|---|---|
| `00-overview.md` | This document. Architecture, invariants, build order. |
| `01-protocol.md` | `ramen-proto`: framing, envelopes, handshake, error taxonomy, `Fault`. |
| `02-audit.md` | `ramen-audit`: record format, hash chain, group-commit writer, verifier. |
| `03-supervisor.md` | `ramen-supervisor`: socket lifecycle, peer identity, connection state machine. |
| `04-guard.md` | Authorization: Biscuit verification, denial classification, capability model, deny path. |
| `05-operations.md` | The two v0 operations: `Whoami`, `FileWrite`. Reversibility handling. |
| `06-ramenctl.md` | `ramenctl`: CLI client, protocol conformance harness. |

Read `01` before writing any code. Every other component is a consumer of the
shape it defines.

## Non-negotiable invariants

These hold in every code path. A change that violates one of these is a bug
regardless of what it enables.

1. **No unmediated action.** The supervisor performs an effect only after a
   successful authorization decision for that specific operation. There is no
   code path that reaches an effect without passing through the guard.

2. **Audit precedes effect.** For any operation that mutates state — including
   preparatory effects such as the snapshot taken before a write (see
   `05-operations.md`) — the audit record is written and `fsync`ed to disk
   *before* the effect is performed. A crash between audit and effect leaves a
   recorded intent with no effect. A crash in the other order would leave an
   unrecorded effect, which is unacceptable.

3. **Denials are audited.** A denied request produces an audit record with the
   same rigor as an authorized one. The deny path is not a shortcut.

4. **No silent degradation.** If the supervisor cannot enforce — audit log
   unwritable, root key unavailable, peer identity unverifiable — it refuses
   service. It never continues in a reduced-enforcement mode. Failure is loud
   and terminal for the affected connection.

5. **The control plane is not an operable surface.** No operation exposed over
   the protocol can read, write, or influence the supervisor's own
   configuration, audit log, key material, or socket. This is enforced by not
   implementing such operations, and by path checks in the ones that touch the
   filesystem.

6. **Authorization structure and audit integrity are separate mechanisms.**
   Biscuit answers "is this caller permitted to do this." The hash chain
   answers "has the record been altered." Neither substitutes for the other.

## Component boundaries

```
                    ┌──────────────────────────┐
   agent / CLI ────►│  AF_UNIX SOCK_STREAM     │
                    └───────────┬──────────────┘
                                │ length-prefixed JSON  (01-protocol)
                    ┌───────────▼──────────────┐
                    │  ramen-supervisor        │
                    │  ┌────────────────────┐  │
                    │  │ peer identity      │  │  (03-supervisor)
                    │  ├────────────────────┤  │
                    │  │ guard              │  │  (04-guard)
                    │  ├────────────────────┤  │
                    │  │ audit append       │  │  (02-audit)
                    │  ├────────────────────┤  │
                    │  │ operation executor │  │  (05-operations)
                    │  └────────────────────┘  │
                    └──────────────────────────┘
```

`ramen-proto` and `ramen-audit` are pure with respect to the rest of the
system: `ramen-proto` has no I/O at all, and `ramen-audit` talks to exactly one
file handle plus its own writer thread. They are unit-testable without a
socket. Keep them that way.

## Repository layout

Single Cargo workspace.

```
ramen/
  Cargo.toml                 # [workspace]
  crates/
    ramen-proto/             # envelopes, codec, reversibility  (no I/O)
    ramen-audit/             # append-only log + verifier; ships the
                             # `ramen-audit-verify` binary
    ramen-guard/             # biscuit verification, policy evaluation
    ramen-supervisor/        # the daemon binary
    ramen-sdk/               # client library agents link against
  cli/
    ramenctl/                # CLI client + conformance harness
    ramen-mint/              # root key custody + token minting. A separate
                             # binary that never links into the supervisor;
                             # the root private key never enters supervisor
                             # configuration
  spec/                      # THIS DIRECTORY, vendored into the repo
  docs/
```

**The spec moves with the code.** `spec/01-protocol.md` and `ramen-proto` change
in the same commit. Add a CI check that fails when files under
`crates/ramen-proto/src/` change without a corresponding change under
`spec/`. If they are allowed to drift, the spec stops being authoritative and
becomes documentation, which is a different and much less useful artifact.

## Toolchain

- Rust, edition 2021, MSRV pinned in `rust-toolchain.toml`.
- `#![forbid(unsafe_code)]` in every crate except `ramen-supervisor` and
  `ramen-audit`. `ramen-supervisor` needs `unsafe` for `getsockopt` and the
  Security framework FFI; `ramen-audit` needs it for `F_FULLFSYNC`. Confine
  each crate's `unsafe` to a single module (`platform::darwin` in the
  supervisor, `fullfsync` in the audit crate) and document each block.
- `#![deny(warnings)]` in CI, not in local builds.
- Target platform for v0: macOS 13+ on Apple Silicon and x86_64. Linux support
  is not a v0 goal, but do not gratuitously prevent it — put platform-specific
  code behind `#[cfg(target_os = "macos")]` with a compile error stub for other
  targets rather than scattering assumptions.

## Dependencies

Prefer a small, auditable set. This process is privileged.

- `serde`, `serde_json` — wire format.
- `biscuit-auth` — capability tokens. **Pin an exact version, 6.x.** P-256
  signature support arrived in 6.0.0 (via biscuit-datalog 3.3); it is not in
  5.x. 6.x also reworked the authorizer API around an extracted
  `AuthorizerBuilder` and made key serialization explicit: the algorithm is
  embedded in the serialized key, and public and private keys are
  differentiated. The latter is what makes the supervisor's
  private-key-in-configuration check (`03-supervisor.md` §1) trivial.
  **If the M0 spike fails: do not fall back to Ed25519-and-remint-later.**
  Keep P-256 and bind the token to the Secure Enclave key with an outer
  signature outside Biscuit. That decouples Biscuit's signing algorithm from
  key custody, which is where the coupling shouldn't have been anyway.
- `sha2` — audit chain hashing.
- `tokio` (`net`, `rt-multi-thread`, `io-util`, `sync`, `macros` features only)
  — async runtime. Do not enable the full feature set.
- `thiserror` — error types.
- `tracing`, `tracing-subscriber` — diagnostics. **Not** the audit log. Keep
  these strictly separate; see `02-audit.md`.
- `ulid` or `uuid` (v7) — request and session identifiers.
- `core-foundation`, `security-framework` — code signing verification. If the
  needed APIs are not exposed by `security-framework`, declare the `extern "C"`
  bindings in `platform::darwin` rather than pulling in a heavier crate.

Do not add a dependency to `ramen-proto` beyond `serde` and the id crate.
`ramen-audit` additionally takes `tokio` with the `sync` feature only (mpsc /
oneshot for the group-commit writer); no runtime features in that crate.

## Build order

Each milestone is complete when its acceptance criteria pass. Do not begin a
milestone before the previous one is complete. The value of this ordering is
that when something breaks you know which layer broke.

**M0 — biscuit spike + `ramen-mint`.** Everything before code: verify the
pinned `biscuit-auth` 6.x. P-256 keygen / mint / attenuate / verify is a
documentation-reading exercise now; the spike is for what is actually
uncertain: (a) `starts_with` in a check clause, (b) whether
`Authorizer::query` sees what denial classification (`04-guard.md` §5) needs
to see. Then build `ramen-mint`: `keygen`, `issue` (with `--expires`),
`attenuate` (no key required), `inspect`. M4 cannot be tested without a
minter, so M0 gates everything.

* Spike status (2026-07): **complete, both items confirmed.**
`starts_with` works in check clauses; `Authorizer::query` sees token facts
after a failed authorization. The spike also established three facts now
encoded in `04-guard.md`: `check if` is a positive constraint; the decision
entry point is `authorize()` (not `run()`); and the `TokenExpired` probe must
be **far-past**, because a "valid until" token flips to allow in the past, not
the future.

**M1 — `ramen-proto`.** Types and codec. No I/O. Round-trip and malformed-input
tests. See `01-protocol.md`.

**M2 — `ramen-audit`.** Append-only log, hash chain, group-commit writer,
standalone verifier binary. Tests for tamper detection and truncation. See
`02-audit.md`.

**M3 — supervisor skeleton.** Listen, accept, frame, resolve peer identity,
handshake. No operations yet; every request returns `Error/NotImplemented`,
and that response is audited as `Errored`. See `03-supervisor.md`.

**M4 — guard.** Biscuit verification and denial classification wired into the
request path. Both the authorize and deny paths audited. Still no operations.
See `04-guard.md`.

**M5 — `Whoami`.** First operation. No side effects. Exercises socket, framing,
peer identity, token verification, and audit append end to end. See
`05-operations.md`.

**M6 — `FileWrite`.** First mutating operation. Forces `clonefile(2)`, the
mode-specific write mechanics, and the reversibility model into the design.
See `05-operations.md`.

**M7 — `ramenctl`.** Second binary speaking the protocol. This is the first real
test of whether `01-protocol.md` is sufficient to implement a client without
reading supervisor source. See `06-ramenctl.md`.

## Decisions made for the agent

Three protocol questions were open. They are resolved here because they block
M1. Each is marked with its rationale so it can be revisited before
implementation starts. If any is overridden, `01-protocol.md` changes first.

**D1 — `Pending` does not block, and does not poll.** The connection is
multiplexed by request id. `Pending` is a *non-terminal* response: the
supervisor may send it, then later send a terminal response carrying the same
id on the same connection. Other requests proceed meanwhile.
*Rationale:* blocking creates head-of-line stalls on a connection that may carry
unrelated work; polling puts liveness in the client's hands and generates audit
noise. Multiplexing costs a request-id map and nothing else.
**Not implemented in v0.** No v0 operation emits `Pending`, and the SDK
returns `SdkError` on an unrecognized status (`01-protocol.md` §7). This
decision is preserved so the first operation that needs it does not reopen the
question.

**D2 — `session` is distinct from the Biscuit identity, not derived from it.**
The session id is assigned by the supervisor at handshake and is scoped to one
connection. Audit records carry both `session` and the token's identity.
*Rationale:* one identity legitimately holds several concurrent connections, and
a session must be terminable without revoking a token. Deriving one from the
other collapses two independently useful lifetimes.

**D3 — `ProcSpawn` (PTY vs. pipe triple) and env-var policy are out of scope for
v0.** These are operation-local, do not affect the envelope, and are properly
decided alongside the PTY host milestone.

## Deliberately faked in v0

**Root key custody.** The Secure Enclave is the destination, but v0 uses a
file-backed P-256 key. Define a `RootKey` trait in `ramen-guard` with a single
`public_key` responsibility — verification only, the supervisor never mints —
implement `FileRootKey` behind it, and keep the trait boundary clean enough
that `SecureEnclaveRootKey` is a drop-in later. **Use P-256 / secp256r1 from
day one**, not Ed25519 — the Secure Enclave only does P-256, and discovering
an algorithm mismatch after tokens exist in the wild is an expensive migration.
The trait boundary is the deliverable here; the file backend is scaffolding.

**Managed mode.** Local mode only. No attestation, no remote issuance. Do not
add configuration hooks in anticipation.

**`Pending`.** The protocol mechanics are defined by D1, but no v0 operation
emits the status and the SDK rejects unknown statuses. Adding `Pending` later
is a wire change; that is acceptable because `01-protocol.md` §4 already
refuses version negotiation in v0.

## Out of scope for v0

Do not implement, and do not add extension points for: microVM/libkrun
sandboxing, Endpoint Security framework interception, attestation of any kind,
GUI or GUI generation, marketplace, peer federation, PTY hosting, filesystem
snapshots beyond `clonefile`, prompt-injection defenses.

Speculative extension points are a cost, not an investment. Add them when the
second consumer exists.

## One scheduling note outside the code

The `com.apple.developer.endpoint-security.client` entitlement has an approval
process with real lead time and is required before OS-layer interception can be
built or tested. It is not needed for v0, but the request should be filed early
enough that approval is not the thing gating that milestone.

## Revision history

**v0.2.** M3 empirical correction: the CI peer-pinning form changes from a
`cdhash` requirement to an `identifier` requirement. The requirement-language
`cdhash` term only accepts 20-byte (SHA-1) hashes and does not match
SHA-256-signed code, which is what all modern ad-hoc signatures use (verified
on macOS 26: `cdhash` requirements built from a binary's SHA-256
code-directory hash fail `SecCodeCheckValidity` on that same binary, and the
toolchain cannot produce SHA-1 signatures). See `03-supervisor.md` §2 for the
full note and trust-model rationale.

**v0.1.** Resolutions from the review of v0.0 (the original
draft in `.temp/`):

1. `ramen-mint` added (M0): the token minter was unspecified, and M4–M7 were
   untestable without it. The root private key never enters supervisor
   configuration; the supervisor refuses to start if `root_key_path` parses as
   a private key.
2. `biscuit-auth` pinned to 6.x (P-256 is not in 5.x); the M0 spike is scoped
   to `starts_with` and `Authorizer::query` visibility; the fallback is an
   outer signature over the Secure Enclave key, not Ed25519.
3. `state_dir` added to the supervisor configuration; snapshots live under it;
   its entire subtree is control-plane protected.
4. Denial classification specified: the full authorizer run is authoritative;
   probes run in order after a deny (`CapabilityNotGranted`,
   `ReversibilityNotPermitted`, far-past re-run → `TokenExpired`,
   `ConstraintViolated` catch-all). The M0 spike found the probe direction in
   the original decision inverted and corrected it: a "valid until" token
   flips to allow at a far-past `now`, never at a far-future one. Expiry is a
   check clause; the `expires_at` fact is advisory; `token_expires_at` is
   `Option`.
5. `require_valid_signature` and `allowed_signing_ids` deleted; replaced by a
   raw `requirement` string. CI uses ad-hoc signing plus a pinned
   `identifier` — the real identity path, no certificate. (v0.1 said `cdhash`
   pinning; M3 found the requirement-language `cdhash` term cannot match
   SHA-256-signed code — the only form modern ad-hoc signatures use. See
   `03-supervisor.md` §2.)
6. The `RootKey` description in this file aligned with `04` (`public_key`).
7. `Errored` record kind added; M3's `NotImplemented` responses are audited as
   `Errored`.
8. The verifier checks **every** `Authorized` record, not only mutating ones
   (uniform; the verifier has no mutability knowledge).
9. Snapshot names are `<session_id>.<request_id>.<sanitized_basename>` —
   uniqueness from the supervisor-generated session id, not the client.
10. Over-length `client` fields: truncated and recorded, non-fatal.
11. Final-component symlinks: categorical `Denied/ConstraintViolated`.
12. Write mechanics split by mode: `Create` is a direct `O_CREAT|O_EXCL`
    write; `Overwrite` is temp+rename; the residual `Overwrite`-can-create
    race is documented.
13. M6 reordered to audit → snapshot → write: the snapshot is a state mutation,
    and invariant 2 covers it.
14. `AuditLog::open` recovers a partial trailing frame: truncate, then append
    an audited `TailTruncated` record.
15. Audit `append` is async on a dedicated writer thread with group commit
    (one `F_FULLFSYNC` per drain).
16. Request ids are single-use for the lifetime of the connection; the
    supervisor's per-connection seen-set is capped at 65,536, after which the
    connection is closed with `Fault`.
17. `Pending` cut from the v0 protocol (mechanics preserved in D1); the SDK
    returns `SdkError` on unknown statuses.
18. `Fault` message type introduced: no id, always terminal, always followed by
    close.

Also: `client` metadata is recorded on the `SessionOpened` record; clean tail
truncation of the audit log is documented as undetectable in v0 (it requires
an external anchor and is a post-v0 concern).
