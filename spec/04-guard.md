# 04 — `ramen-guard`

Milestone M4. Authorization wired into the request path. Both the authorize and
deny paths audited. **Still no operations** — the guard runs, reaches a
decision, records it, and the dispatcher then returns `NotImplemented`.

Separating this from M5 means the guard is exercised and tested before any code
path exists that can produce an effect. If the guard is wrong, nothing has
happened yet.

Dependencies: `biscuit-auth` (exact pin, 6.x — see `00-overview.md`
Dependencies), `ramen-proto`, `thiserror`. `ramen-guard` does **not** depend on
`ramen-audit` — it returns a decision, and the supervisor records it. Keeping
the guard free of I/O keeps it unit-testable against a table of tokens.

## 1. Token shape

Biscuit tokens. The root keypair is **P-256 / secp256r1**, not Ed25519, because
the Secure Enclave supports only P-256 and this is the algorithm that must not
change once tokens exist. P-256 support exists in `biscuit-auth` 6.x (via
biscuit-datalog 3.3), not 5.x; the M0 spike confirms the pinned version
end-to-end.

### Authority block

Minted by the root key. Contains the identity and the base capability grant.

```datalog
identity("agent:planner");
capability("Whoami");
capability("FileWrite");
allowed_prefix("FileWrite", "/Users/austin/work");
reversibility_allowed("Trivial");
reversibility_allowed("Compensable");
expires_at(2026-08-31T00:00:00Z);   # optional — see expiry convention
```

**Expiry convention.** Token expiry is a `check` clause
(`check if date($t), $t < ...`) — and check clauses are **not** in general
extractable: a token can carry several, in attenuation blocks, with arbitrary
predicates. `ramen-mint issue --expires` writes both the `expires_at` fact and
the time check. The check is authoritative; the fact is advisory metadata that
only `Whoami` reports (`05-operations.md`). If the two disagree, the check wins
and the fact is a lie — which is fine, because nothing reads the fact except
human-facing output.

**Check-clause semantics (biscuit 6.x).** `check if P` is a *positive*
constraint: the check passes iff the body is satisfiable (at least one binding).
`check if reject P` is the negative form. This is the opposite of the
"a check is a forbidden pattern" intuition, and it is why the expiry check is
written as `$t < EXPIRY` (valid *until* EXPIRY) rather than its negation. The
M0 spike verified this against the engine; do not "simplify" the token examples
based on intuition.

### Attenuation

Any holder can add blocks. Blocks may only add `check` clauses; they cannot add
facts that grant. This is Biscuit's model and it is the reason it was chosen:
delegation is monotonically restrictive without the delegator needing to
consult the issuer.

```datalog
check if operation($op), $op == "FileWrite";
check if path($p), $p.starts_with("/Users/austin/work/scratch");
check if date($t), $t < 2026-08-31T00:00:00Z;
```

A sub-agent receives an attenuated token. The supervisor does not need to know
the delegation happened; the token carries it.

## 2. What Biscuit is and is not doing here

Biscuit provides **authorization structure**: who holds what capability, and how
a capability narrows under delegation. It does not provide audit integrity —
that is the hash chain in `02-audit.md` — and it does not provide identity
verification of the calling process — that is `03-supervisor.md` §4.

These three are independent and must not be conflated. A valid token from an
unverifiable process is refused. A verified process with no token is refused. A
valid decision that cannot be audited is refused (invariant 4). Each mechanism
answers one question and none of them substitutes for another.

## 3. Interface

```rust
pub struct Guard {
    root: Box<dyn RootKey>,
    // compiled policy, clock source
}

pub struct AuthzRequest<'a> {
    pub token: &'a Biscuit,
    pub op: &'a Operation,
    pub now: OffsetDateTime,
}

pub enum Decision {
    Allow,
    Deny { code: DenialCode, reason: String },
    Indeterminate { reason: String },
}

impl Guard {
    pub fn authorize(&self, req: AuthzRequest<'_>) -> Decision;

    /// Best-effort summary for the Welcome message. Advisory only.
    pub fn describe_capabilities(&self, token: &Biscuit) -> Vec<CapabilitySummary>;
}
```

`authorize` returns `Decision`, not `Result<(), E>`. A denial is a normal
outcome of a working system, and `Result` invites `?` propagation that would
merge denials into the error path. `01-protocol.md` §7 explains why that
distinction matters; the type should enforce it.

`Indeterminate` is the third outcome, for the case the first two cannot cover:
the guard *could not reach a decision*. The datalog engine can fail the
evaluation itself — a wall-clock limit under load, an engine-internal error —
and that failure is not a denial: the token has not been shown to be
insufficient, only that the guard could not finish checking. It refuses the
operation (fail closed, exactly like `Deny`) but is **not classified** — the
classification probes are differentials against a primary result, and a failed
primary provides none (§5, §9). On the wire it maps to
`Error/EvaluationIncomplete`, never `Denied`; in the audit log it is its own
record kind. The distinction is operationally load-bearing: a burst of
denials means a misconfigured agent, and a burst of indeterminates means the
supervisor is under resource pressure or someone is feeding it pathological
tokens — and the second is the one that is an attack.

### `RootKey`

```rust
pub trait RootKey: Send + Sync {
    fn public_key(&self) -> PublicKey;
}
```

Verification only. The supervisor in local mode never mints tokens at runtime —
minting is an out-of-band operation performed by `ramen-mint`. A process that
can both verify and mint is one bug away from minting for itself.

`FileRootKey` reads a P-256 public key from disk. `SecureEnclaveRootKey` will
implement the same trait later. The trait boundary is the deliverable; the file
backend is scaffolding. (`00-overview.md` describes this trait in the same
shape; it is authoritative here.)

## 4. Authorizer construction

For each request, build a fresh `Authorizer` (via `AuthorizerBuilder` in
biscuit 6.x). Never reuse one across requests — fact accumulation across
requests is a privilege-escalation bug waiting to happen, and it would be
subtle.

Facts added by the supervisor, from **trusted** sources only:

```datalog
operation("FileWrite");
reversibility("Trivial");
date(2026-08-30T14:07:33Z);
path("/Users/austin/work/notes.md");   // canonicalized — see §6
```

Then the policy:

```datalog
allow if
  operation($op),
  capability($op),
  reversibility($r),
  reversibility_allowed($r);

deny if true;
```

The trailing `deny if true` is mandatory. Biscuit evaluates policies in order
and a token with no matching allow must not fall through to a permissive
default.

**The decision entry point is `Authorizer::authorize()`**, which runs the world
and then evaluates all check clauses and policies, returning the matched policy
or a `FailedLogic` error. `Authorizer::run()` only derives facts: it never
evaluates checks or policies, so it can never produce a denial and must never
be used as the decision. (The M0 spike lost an hour to this: every denial
looked like an allow until `authorize()` was called.)

**Every authorizer is built with explicit evaluation limits, and an
evaluation failure can never become a `Deny`.** biscuit-auth's datalog engine
defaults to a **1 ms wall-clock limit** (`RunLimits::default`); under load, a
perfectly valid token's evaluation can exceed it and the engine returns
`Err(RunLimit(Timeout))` instead of a decision. Two layers of defense, in
order: (1) the token depth cap (`07-delegation.md` §4) already bounds token
complexity, so the guard raises the limits generously (seconds, not
milliseconds) — which makes an engine-limit failure *rare*; (2) if an
evaluation still does not complete, the guard returns `Indeterminate` (§3,
§9) — which makes it *safe*. The second layer is the safety property: a
`Deny` means the guard reached a decision and it was no; `Indeterminate`
means it did not reach one, and the classification probes — differentials
against a primary result — are meaningless without one. Raising the limits
alone is not a fix, because wall-clock limits are load-dependent and 1 s under
a bad enough scheduler is the same 1 ms problem with more headroom. Tests pin
both edges: the defaults exceed biscuit's 1 ms floor, and a forced `RunLimit`
error (zero time limit — deterministic, load-independent) yields
`Indeterminate`, never `Deny`, and specifically never `TokenExpired` (the
misclassification a primary-less probe run produced).

**Facts must never be derived from client-supplied metadata.** The `client`
field in `Hello` (`01-protocol.md` §5) is attacker-controlled and goes only to
the audit record. Peer signing id likewise: it is recorded, not authorized on.
The moment a signing id becomes an authorizer fact, a valid signature starts
granting authority, which is exactly the ambient-authority failure that
`03-supervisor.md` §4 warns about.

## 5. Denial classification

The authoritative decision is **always the full authorizer run** (with the
`deny if true` trailer). Classification is a diagnostic that only executes
after that run has already returned deny. There is no path from the classifier
to `Allow`.

```rust
fn authorize(&self, req: &AuthzRequest) -> Decision {
    match self.run_authorizer(req) {      // full run, `deny if true` trailer
        Ok(allow) if allow => Decision::Allow,
        // Evaluation **completed** with a no: a deny policy matched, or a
        // check failed (biscuit reports check failures as
        // `Err(FailedLogic)` — expiry is a check). Deterministic;
        // classify by probing.
        Ok(_) | Err(FailedLogic) => Decision::Deny { code: self.classify(req), .. },
        // Token-derived engine faults (format, encoding, datalog language,
        // term conversion, an unevaluatable expression in the token's own
        // checks): the *token* failed, deterministically. Rejected.
        Err(token_fault) => Decision::Deny { code: TokenRejected, .. },
        // Machine-derived engine faults (RunLimit, internal): the
        // evaluation did **not** complete; probes — differentials against a
        // primary result — are meaningless. Fail closed, unclassified (§9).
        Err(machine_fault) => Decision::Indeterminate { .., limits: self.eval_limits },
        // Anything the guard does not recognize as token-fault or
        // machine-fault — today: builder-side states (append/seal on a
        // sealed token) that `authorize` never constructs. Indeterminate,
        // never `panic!`: a panic in the guard is a supervisor crash
        // triggered by an attacker-supplied token — every in-flight session
        // drops. Fail closed, name the variant in the record (§9).
        Err(unexpected) => Decision::Indeterminate { .., limits: self.eval_limits },
    }
}
```

The match is **exhaustive over the engine's error enum, with no wildcard
arm.** A biscuit-auth bump that adds an error variant is a compile error
here, to be classified deliberately as token-fault or machine-fault — not a
new failure mode silently inheriting `Indeterminate` (the same reasoning as
the encoding pins in `07-delegation.md` §5). The split is by *who* is at
fault: token-derived faults are deterministic — the same token always fails
the same way — and are denials of that token; machine-derived faults
(engine limits under load, engine-internal errors) are not the token's
fault and must never be dressed up as a denial of it.

`Indeterminate` deliberately carries the evaluation limits — captured from
the guard at decision time, i.e. the parameters the evaluation **actually
ran under**, not a configuration read — and the reason names the engine's
error. The unexpected-variant arm exists because "unreachable today" is an
argument about what the library currently returns, and the whole point of
the exhaustive match is not trusting that to stay true. The decision
procedure has no panic path: a panic in the guard is a supervisor crash
triggered by an attacker-supplied token, dropping every in-flight session —
the worst outcome available. Reserve `panic!` for states where continuing
would be *less* safe than stopping; an unrecognized engine error is not
one.

`classify` probes in order with `Authorizer::query`; the first probe that fires
determines the code:

1. No `capability($op)` for the requested operation → `CapabilityNotGranted`.
2. No `reversibility_allowed($r)` for `r = op.reversibility()` →
   `ReversibilityNotPermitted`.
3. **Time probe:** re-run the full authorizer with `now` replaced by a
   far-past instant (e.g., `now - 10 years`). If that run allows, the original
   denial was time-based → `TokenExpired`.
4. Otherwise → `ConstraintViolated`.

`TokenRejected` is **not** a probe outcome: it is assigned directly, before
any probe, when the engine surfaces a token-derived fault (§5's match). A
token whose format, encoding, datalog, or internal expressions the engine
cannot process is rejected as a token, the way a token with a bad signature
is rejected — not classified as if the evaluation had run.

The time probe is **far-past, not far-future**. A "valid until" check
(`date($t), $t < EXPIRY`) is satisfied only at times before the expiry: an
expired token denied at `now` flips to allow at a far-past `now` and is still
denied at a far-future `now`. A far-future probe would only fire for tokens
with an *activation* window (`date($t) > START`), which `ramen-mint` never mints
in v0, so it is cut. The M0 spike verified the flip direction empirically.

The `FailedLogic` error returned by `authorize()` names the exact failed check
clause; implementations may use it as an aid when constructing `reason`, but
the probes above remain the specified classification mechanism — they are
robust across biscuit versions and do not depend on error-payload shapes.

`ConstraintViolated` is the catch-all, and that is correct: it is the least
informative code and the one that should absorb anything unclassifiable. The
probe order is deterministic — a token with multiple faults reports the first
probe that fires.

`reason` describes the policy failure class. It never contains data derived
from the operation's target contents (`01-protocol.md` §7).

## 6. Path canonicalization — get this right

Any path-valued fact must be fully canonicalized **before** it enters the
authorizer, and the canonical form must be what is executed on. Anything else is
a TOCTOU.

Procedure:

1. Reject non-absolute paths outright (`ConstraintViolated`).
2. Reject any path containing a `..` component **lexically**, before touching
   the filesystem.
3. Resolve symlinks on the parent directory.
4. Re-check the resolved parent against the allowed prefix.
5. **If the final component exists and is a symlink → `ConstraintViolated`.**
   The refusal is categorical, not a prefix check in disguise:
   canonicalizing through the link would mean the client asked to write A and
   Ramen wrote B, which is a worse failure than refusing.
6. Execute against the resolved path, not the string the client sent.

The gap between checking a path and using it is the classic filesystem
authorization bug: a client passes a path that checks out, then replaces a
component with a symlink before the write. Steps 3–6 close it by making the
checked object and the used object the same object.

Prefix matching is **component-wise**, not string-prefix. `/Users/austin/work`
must not match `/Users/austin/workspace-secrets`. A naive `starts_with` on the
string form has exactly this bug and it is easy to ship.

## 7. Control plane protection

Before any other check, reject operations whose canonicalized target resolves
inside Ramen's own state: `socket_path`, `audit_path`, `root_key_path`, the
config file, `state_dir` **and its entire subtree** (it is a directory;
everything under it — including `snapshots/` — is control-plane state), or the
containing directory of any of the file paths. Denial code
`ControlPlaneProtected`.

This is invariant 5 and it is checked in the guard, not left to the operation
implementations. Putting it in one place means adding an operation cannot
accidentally omit it.

Compare against canonicalized configured paths computed once at startup.

## 8. Clock

Take the clock as an injected `now` rather than calling `OffsetDateTime::now()`
inside `authorize`. Time-based checks are otherwise untestable, and the tests
that matter here are the ones about expiry boundaries.

Use the system clock, not a monotonic one — token expiry is wall-clock. Note as
a known limitation that a client who can move the system clock backward can
extend token validity. In local mode this is inside the threat model already
(the attacker owns the machine); it becomes real in managed mode, which is where
Roughtime or a similar freshness source belongs. Do not build that now.

## 9. Failure handling

`authorize` never panics. There is no path from an internal fault to
`Allow`, and there is no path from a failed evaluation to a classified
`Deny`. The fault classes map to exactly three outcomes, decided by an
**exhaustive match over the engine's error enum — no wildcard arm** (§5):

- **The evaluation completed with a no** — the token lacks a capability, a
  check failed, a `deny if true` matched. This is `Deny`, classified (§5).
  Check failures (`FailedLogic`) are *completed* evaluations: the datalog ran
  to a fixpoint and the check was evaluated. They are deterministic, and the
  classification probes are valid differentials against them — which is
  exactly how expiry is distinguished from other check failures. This split
  rests on a structural assumption about the engine — that a failed check
  surfaces as `Err(FailedLogic)`, not as a deny-policy match or a success —
  and it is pinned by the test
  `expired_token_denies_with_token_expired` (an expired token must classify
  as `TokenExpired` through the probes, not fall into `Indeterminate`). If a
  biscuit-auth bump changes how check failures surface, that test fails, and
  its failure means the `FailedLogic` bucket — and therefore which failures
  get classified at all — must be re-examined before the bump is accepted.
  The test is the tripwire; this sentence is what its failure means.
- **The evaluation completed and the token is at fault** — the engine
  surfaced a token-derived failure (format, encoding, datalog language, term
  conversion, an unevaluatable expression in the token's own checks).
  This is `Deny/TokenRejected`, assigned directly without probing: the
  token is rejected, like one with a bad signature.
- **The evaluation did not complete** — an engine limit (`RunLimit`), an
  engine-internal error, or an engine error the guard does not recognize as
  a token fault (never a panic: see §5). This is `Indeterminate`: refuse
  the operation (fail closed), do not classify, skip the classification
  probes entirely — a probe result is only meaningful as a differential
  against a primary result that exists. On the wire: `Error/
  EvaluationIncomplete`. In the audit log: an `Indeterminate` record
  carrying the reason, the **limits the evaluation actually ran under**
  (captured in the decision, not read from configuration), and two advisory
  streaks — the session's consecutive-indeterminate count and the
  supervisor-wide one (`02-audit.md`): a load-induced burst is one
  indeterminate on each of many sessions, so per-session counts read 1
  while the supervisor-wide count climbs; a single pathological client
  climbs the per-session count on one session only. A wall-clock-bounded
  evaluation means a decision is no longer a pure function of token, facts,
  and clock — it is also a function of machine load. A decision is therefore
  **reproducible only in the absence of `Indeterminate`**: an auditor
  re-running a completed decision gets the same answer; an `Indeterminate`
  record is a flag that the machine, not the token, was the variable, and
  the recorded limits say under what budget it ran.

Token parsing happens before `authorize` (at handshake) and a parse failure is a
handshake failure. But `authorize` still defends against a malformed token
reaching it, because "that can't happen" is not a safety property.

## 10. Dispatch integration (M4 form)

```rust
async fn dispatch(ctx: &SessionCtx, req: Request) -> Response {
    let decision = ctx.guard.authorize(AuthzRequest {
        token: &ctx.token,
        op:    &req.op,
        now:   ctx.clock.now(),
    });

    match decision {
        Decision::Deny { code, reason } => {
            let seq = ctx.audit.append(&Record::denied(&req, code, &reason)).await?;
            Response::denied(req.id, code, reason, seq)
        }
        Decision::Indeterminate { reason } => {
            // Failed evaluation: refuse, but as its own record kind and wire
            // code, with the limits in force (§9).
            let seq = ctx.audit.append(&Record::indeterminate(&req, &reason, limits)).await?;
            Response::error(req.id, ErrorCode::EvaluationIncomplete, reason)
        }
        Decision::Allow => {
            ctx.audit.append(&Record::authorized(&req)).await?;   // BEFORE effect
            // M4: no effect exists yet.
            Response::error(req.id, ErrorCode::NotImplemented, "not available in v0")
        }
    }
}
```

The `Authorized` record is written before the effect even in M4, where there is
no effect. The ordering is established now so that M5 inserts the effect into a
sequence that is already correct, rather than reordering a sequence that was
convenient.

## 11. Acceptance criteria (M4)

- [ ] Root keypair is P-256. Assert the curve in a test, not just in a comment.
- [ ] Token with `capability("Whoami")` → `Allow` for `Whoami`.
- [ ] Same token → `Deny/CapabilityNotGranted` for `FileWrite`.
- [ ] Attenuated token that removed `FileWrite` → denied, while the parent token
      is still allowed. Both from the same test to prove attenuation is real.
- [ ] Expired token → `Deny/TokenExpired` via the time probe (not
      `ConstraintViolated`). Test at `expiry - 1s`, `expiry`, and `expiry + 1s`
      and assert the boundary behavior explicitly.
- [ ] Token lacking the capability → `Deny/CapabilityNotGranted`, distinct from
      `ConstraintViolated` (classification order, §5).
- [ ] Token signed by a non-root key → denied. Never allowed, never an error.
- [ ] Forced engine-limit failure (zero time limit, deterministic) →
      `Indeterminate`: the operation is refused, the wire response is
      `Error/EvaluationIncomplete` (not `Denied`), the audit record is
      `Indeterminate` with the limits in force, and the outcome is never
      `Deny` — specifically never `TokenExpired`. A burst of these is
      resource pressure or a pathological-token attack; it must stay
      distinguishable from a burst of denials.
- [ ] Malformed and truncated token bytes → denied, no panic. Fuzz this.
- [ ] Path escaping the allowed prefix via `..` → denied at step 2, before any
      filesystem access. Assert no `stat` occurs (inject a filesystem trait, or
      point the path at a location whose access would be observable).
- [ ] `/Users/austin/workspace-secrets/x` denied against prefix
      `/Users/austin/work`. This is the component-wise matching test and it must
      exist.
- [ ] Symlinked parent directory pointing outside the prefix → denied.
- [ ] Final component is a symlink whose target is **inside** the allowed
      prefix → denied. This proves the refusal is categorical rather than a
      prefix check in disguise.
- [ ] Final component is a symlink whose target is outside the prefix → denied.
- [ ] Each of `socket_path`, `audit_path`, `root_key_path`, the config file,
      `state_dir`, a path inside the `state_dir` subtree, and the parent
      directories of the file paths → `Deny/ControlPlaneProtected`, tested
      individually.
- [ ] A path reaching control-plane state via symlink → also
      `ControlPlaneProtected`. This is the test that proves the check runs after
      canonicalization rather than on the raw string.
- [ ] Two sequential requests on one connection use distinct authorizers —
      construct a token whose first request adds a fact, assert the second does
      not see it.
- [ ] Every denial variant produces an audit `Denied` record whose `audit_seq`
      matches the one returned to the client.
- [ ] `#![forbid(unsafe_code)]`. The guard has no reason to need it.
