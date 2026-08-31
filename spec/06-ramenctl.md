# 06 — `ramenctl` and `ramen-sdk`

Milestone M7. A second binary that speaks the protocol.

## 1. Why a CLI and not the Tauri shell

The point of building a second client this early is to test whether
`01-protocol.md` is sufficient to implement a client **without reading
supervisor source**. A CLI is the cheapest thing that provides that test. The
Tauri shell would prove nothing the CLI has not already proved, and it would
bring a UI framework, a build pipeline, and a code-signing story into a
milestone whose actual purpose is protocol validation.

The desktop shell's role in the architecture is "thin client of a documented
Unix socket protocol." That claim is only true if the protocol document is
genuinely sufficient, and M7 is where that gets verified.

### How to run this milestone

Implement `ramen-sdk` **from `01-protocol.md` alone**. Do not import types from
`ramen-proto`, do not read `ramen-supervisor` source, and do not consult the
supervisor's tests. Define the envelope types independently from the spec text.

Then, as the final acceptance step, add a test that asserts the SDK's
independently-defined types round-trip against the golden fixtures committed in
M1. Every mismatch found is a defect **in the spec**, not in the SDK. Fix the
spec, then reconcile.

After that test passes, the SDK may depend on `ramen-proto` for real, and the
duplicated types collapse into it. The duplication is a measuring instrument,
not a design.

## 2. `ramen-sdk`

The library agents link against. `ramenctl` is its first consumer, which keeps
the SDK from acquiring CLI-shaped assumptions.

```rust
pub struct Client { /* ... */ }

impl Client {
    pub async fn connect(socket: &Path, token: &UnverifiedBiscuit) -> Result<Self, SdkError>;

    pub fn session(&self) -> SessionId;
    pub fn identity(&self) -> &str;

    /// Resolves on a terminal response.
    pub async fn call(&self, op: Operation) -> Result<OpOutcome, SdkError>;
}

pub enum OpOutcome {
    Ok(serde_json::Value),
    Denied { code: DenialCode, reason: String, audit_seq: u64 },
    Error { code: ErrorCode, message: String },
}
```
The token type is `UnverifiedBiscuit`, not `Biscuit`: in biscuit-auth, `Biscuit`
is a *verified* token — its constructors validate the signature against the
root key — and a client never holds the root key, only the supervisor and the
minter do. The client parses the base64 text into an unverified biscuit and
hands it to the supervisor, which performs the verification at handshake
(`04-guard.md` §3). A client-side "verified" type would have no valid way to
be constructed.

Three things about this signature:

**`Denied` is inside `Ok`, not `Err`.** A denial is a successful round trip that
produced a policy answer. Putting it in the error variant means every `?` in
consumer code treats a denial as a transport failure, and consumers stop
distinguishing them. `SdkError` is for transport, framing, and handshake
failures only.

**`Error` is an outcome, not an `SdkError`.** The `Error` status is one of the
three terminal responses (`01-protocol.md` §7): the round trip succeeded, the
request was matched by id, and the supervisor reported a machinery failure.
It is the request-scoped counterpart of `Denied` — a system answer, not a
transport failure. Surfacing it as `SdkError` would make every `?` in consumer
code treat "the supervisor executed and told me this operation failed" as
"I couldn't reach the supervisor", and a consumer that retries transport
failures would retry an operation the supervisor already reported as failed.
It is a third `OpOutcome` variant for the same reason `Denied` is one.

**Unknown statuses are transport errors.** v0 has exactly three terminal
statuses (`01-protocol.md` §7). An unrecognized status — for example a future
`Pending`, which v0 never emits — surfaces as `SdkError`, not a hang and not a
silent drop. Adding `Pending` later is a wire change; a v0 SDK that sees it
reports it, which is the intended behavior (00-overview.md, D1).

**Concurrency is the SDK's job.** `call` is `&self`, not `&mut self`, so callers
can issue concurrent requests. Internally: request-id map, writer task, reader
task. Responses are matched by id, never by order. If the SDK serializes calls,
the protocol's multiplexing is never exercised.

A `Fault` frame (`01-protocol.md` §7) closes the connection; in-flight calls
resolve with `SdkError`.

## 3. `ramenctl`

```
ramenctl --socket <path> --token <file> <command>
```

Commands:

| Command | Behavior |
|---|---|
| `whoami` | Issues `Whoami`, prints identity, session, capabilities. |
| `write <path>` | Issues `FileWrite`. Content from `--content` or stdin. `--create` selects `Create` mode; default is `Overwrite`. |
| `ping` | Connects, completes handshake, disconnects. Exercises handshake alone. |
| `conform` | Protocol conformance harness (§4). |

Global flags: `--json` for machine-readable output on all commands.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Operation succeeded |
| 1 | Operation denied |
| 2 | Transport, handshake, or protocol error |
| 3 | Usage error |

Denial gets its own exit code for the same reason it gets its own status: a
script that retries on failure should not retry a denial, because the answer
will not change.

Denials print the code, reason, and `audit_seq`. Print the `audit_seq`
prominently — it is the handle an operator uses to find the decision in the log
without trusting the CLI's account of it.

`ramenctl` must satisfy the supervisor's configured peer requirement, or M7
cannot be tested at all. In CI the test binary is signed **ad-hoc**
(`codesign -s -`) and its signing identifier is pinned in the test config
(`requirement = 'identifier "ramen-ctl"'`, read via `codesign -dv` in the build
step) — no certificate required, and the real identity path is exercised
rather than bypassed (`03-supervisor.md` §2; the `cdhash` requirement term
cannot match SHA-256-signed code, so it is not usable for CI). Set up ad-hoc
signing and identifier pinning before writing the CLI, not after.

## 4. `conform` — the conformance harness

This is the most valuable part of M7 and it should not be an afterthought. It
sends deliberately wrong things and asserts the supervisor rejects them
correctly. Every check corresponds to a rule in `01-protocol.md`.

| Check | Send | Expect |
|---|---|---|
| `frame_oversize` | Prefix of `MAX_FRAME_BYTES + 1` | Close without reading body |
| `frame_zero` | Prefix of 0 | Close |
| `frame_split` | Valid request, 1 byte per write | Normal response |
| `bad_utf8` | Prefix + invalid UTF-8 | Close |
| `bad_json` | Prefix + `{` | Close |
| `version_mismatch` | Post-handshake request with `"v": 2` | `Error/VersionMismatch`, close |
| `no_hello` | `Whoami` as first message | Close |
| `double_hello` | `Hello` after `Welcome` | Close |
| `unknown_field` | Request with an extra key | Close (fatal; `Fault` best-effort) |
| `dup_request_id` | `Whoami` with id X, receive the response, send `Whoami` with id X again | Close (`ProtocolViolation`) — deterministic because request ids are single-use for the lifetime of the connection (`01-protocol.md` §3) |
| `unknown_op` | `{"type":"Frobnicate"}` | Close (unknown enum variant) |
| `concurrent` | 16 concurrent `Whoami` | 16 correctly matched responses |
| `out_of_order` | Concurrent ops with varied latency | Responses matched by id, not order |

(`version_mismatch` is tested post-handshake because a request carries an id and
can therefore get an `Error`; a `Hello` with the wrong `v` has no id and gets a
`Fault` — that case is covered by the fatal-violation tests in
`03-supervisor.md` §7.)

`conform` writes each check's outcome and exits nonzero on any failure. Run it
in CI against a supervisor started with a test config.

The harness must construct malformed frames **directly**, bypassing the SDK. If
it goes through the SDK it can only send things the SDK can express, which is
precisely the set of things that are already well-formed.

## 5. Acceptance criteria (M7)

- [ ] `ramen-sdk` was implemented from `01-protocol.md` with no reference to
      `ramen-proto` source. Verify by commit history — the SDK's initial commit
      must not follow a commit touching `ramen-proto`.
- [ ] SDK types round-trip against M1 golden fixtures. Every discrepancy found
      during this step is recorded as a spec defect in the commit message, and
      `01-protocol.md` is amended.
- [ ] `ramenctl ping` completes a handshake and exits 0.
- [ ] `ramenctl whoami` prints identity and capabilities matching a token minted
      with known contents.
- [ ] `ramenctl write` writes a file; content on disk matches; a restore handle
      is printed.
- [ ] `ramenctl write` to a denied path exits **1**, prints the denial code and
      `audit_seq`, and that `audit_seq` resolves to a matching `Denied` record
      when the log is inspected with `ramen-audit-verify`.
- [ ] Supervisor stopped → exit 2, not 1.
- [ ] `--json` output on every command parses as JSON and contains no ANSI
      escapes.
- [ ] `ramenctl conform` passes every check against a running supervisor.
- [ ] After a full `conform` run, `ramen-audit-verify` on the supervisor's log
      exits 0 or 1 — never 2. A conformance run consists entirely of hostile
      input and must not be able to corrupt the chain. **This is the single most
      important assertion in M7.**
- [ ] SDK issues 16 concurrent calls on one `Client` and matches all responses.
- [ ] Supervisor killed mid-call → SDK returns `SdkError`, does not hang. Assert
      with a test timeout.
- [ ] In CI: `ramenctl` is ad-hoc signed with its identifier pinned in the test
      config; the identity path (audit token → guest code → validity check) is
      exercised, not bypassed.

## 6. What M7 completes

At the end of M7 there is a supervisor that mediates two operations, a
tamper-evident log with an independent verifier, a capability model with real
attenuation, and a second implementation of the protocol built from the spec.

That is the v0 core. The sequenced milestones after it — PTY host with OSC 133,
real agent integration, filesystem snapshots, GUI — all attach to this shape as
consumers rather than modifying it, which was the point of building it in this
order.

Before starting any of them, re-read `00-overview.md` §"Non-negotiable
invariants" against the code as it actually exists. The invariants are easiest
to violate in the milestone where the codebase stops being small.
