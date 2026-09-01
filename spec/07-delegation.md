# 07 — Delegation and attenuation

Milestone M8. The capability model becomes real: a token holder can produce a
strictly weaker token for another agent, the guard enforces the narrowing, and a
compromised or misbehaving delegate can be revoked without reminting anything
upstream of it.

**No new operations.** M8 adds no verbs to `Operation`. Everything here is
exercised through `Whoami` and `FileWrite`, which is the point — the delegation
semantics get settled while the effect surface is still two operations wide.

Dependencies: `ramen-guard`, `ramen-audit`, `ramenctl`. `biscuit-auth` at the
same exact pin as M4; if this milestone requires a version bump, do the bump as
its own commit with the M4 guard tests unchanged and passing.

## 1. Why this precedes `ProcSpawn`

`ProcSpawn` is the operation everything else in Ramen is protecting. It is also
the operation that makes delegation unavoidable: a spawned child is a new peer
on the socket and it needs a token, and the only interesting question about that
token is what it is *not* allowed to do relative to its parent.

If delegation is designed while also debugging fd passing, PTY allocation, and
child process lifecycle, the delegation design will lose. It is the part with no
visible symptoms when it is wrong.

At the end of M8, `ProcSpawn` reduces to: mint an attenuated token, spawn, hand
the child the token and a socket fd. The hard part is already done and tested.

## 2. Attenuation is offline. This is a decision.

A token holder attenuates by appending a block locally, with no supervisor round
trip and no access to the root key. The supervisor learns about the delegation
when the resulting token shows up in a `Hello`.

The alternative — a `TokenMint` operation where the parent asks the supervisor
to issue the child token — was considered and rejected:

- It reintroduces the supervisor as a synchronous dependency of an act it cannot
  make any safer. Attenuation is monotonically restrictive by construction. A
  supervisor asked to approve a narrowing has nothing to check.
- It requires the supervisor to hold minting capability at runtime. `04-guard.md`
  §3 is explicit that a process which can both verify and mint is one bug from
  minting for itself. Keep that property.
- The audit record worth having is not "a token was created." It is "this token
  chain performed this operation," and M8 §7 produces that regardless.

The delegation *edge* — parent P caused child C to exist — is recorded at
`ProcSpawn` time in M9, where a supervisor-mediated action actually occurs. It
is not recorded at attenuation time, because attenuation is not an action the
supervisor participates in.

**Attenuation blocks are key-inherited, not root-signed.** Only the authority
block is signed by the root key (P-256 in v0). Each token carries the private
key that signs its next block (Biscuit's key-inheritance model): the appended
block is signed with that embedded key, and the token then holds the
successor's. In Biscuit's terms this is *first-party* delegation — the same
principal extending its own token. The supervisor verifies the whole chain by
following the inheritance from the root. Attenuation blocks use Biscuit's
default delegable key (Ed25519 under the pinned biscuit-auth), so the P-256
requirement applies to the root key only.

**Third-party blocks are out of scope.** Biscuit supports blocks signed by a
key other than the token holder's, which is the right mechanism for one agent
attesting to another's delegation. It is not needed for parent-to-child spawn
and it drags in key distribution. Do not implement it in M8. Do not design it
out either — no code should assume every block is first-party.

**The token file is a secret.** Key inheritance means each token embeds the
private key that signs its next block: anyone who can read `parent.b64` can
attenuate it further. Consequences the rest of the design must respect:

1. An agent is never handed the parent token, only its attenuation.
2. `ramenctl token attenuate --out` writes `0600` regardless of umask.
3. Token bytes are never logged; the audit trail carries only revocation ids
   (the §5 chain).
4. Short expiries (§11.3) independently bound the damage window of a leaked
   token file.

## 3. `ramenctl token attenuate`

Offline. No socket connection. Reads a token, appends one block, writes a token.

```
ramenctl token attenuate \
  --in parent.b64 \
  --out child.b64 \
  --restrict-op FileWrite \
  --restrict-prefix /Users/austin/work/scratch \
  --expires-in 15m \
  --label "codex:worktree-3"
```

Every flag is restrictive. There is deliberately no flag that adds a capability
or widens a prefix, because there is no such operation — but a CLI that appears
to offer one invites a bug report that ends in someone adding it.

The emitted block contains **checks only** — plus, when `--label` is given,
**one non-authoritative `label` fact**. That "plus" is deliberate and the two
must stay visibly distinct in the emitted block: `07` §9's first anti-goal
forbids fact-*granting* blocks (a `capability()` fact in a non-authority block
voids the monotonicity of the whole model), and a label is only safe because
it is not a grant — no check the guard evaluates may read it (below).

```datalog
check if operation($op), ["FileWrite"].contains($op);
check if path($p), $p.starts_with("/Users/austin/work/scratch/");
check if date($t), $t < 2026-08-31T14:22:00Z;
label("codex:worktree-3");      // the one non-check fact; no check may read it
```

Three things to get right in the generator:

**Prefix checks must end with a separator.** `"/Users/austin/work"` as a
`starts_with` argument matches `/Users/austin/workspace-secrets`. The guard
already does component-wise matching for the authority block's `allowed_prefix`
(`04-guard.md` §5), but a Datalog `starts_with` in an attenuation block is raw
string matching and does not inherit that. Normalize the prefix to end with `/`
when emitting, and reject a prefix that is not absolute or contains `..`.

**Expiry is emitted as an absolute timestamp**, resolved at attenuation time
from the local clock. The token cannot carry a relative duration; there is
nothing to resolve it against at verification time except the supervisor's
clock, which is what §6 is about. `--expires-in` rounds **down** to whole
seconds: `EXPIRY = floor(now, 1s) + N`, and since the check is `<` with second
granularity, an N-minute token is never valid for more than N minutes. The
check references the guard's clock fact, whose name is owned by
`04-guard.md` §4 — this spec does not restate it, so the two documents cannot
drift apart (the `time`/`date` incident of Aug 2026 was exactly that drift).

**`--label` is free-form but length-capped, and never load-bearing.** It goes
into the block as a fact for human legibility in the audit log. It must not be
readable by any check the guard evaluates. Same rule as `rationale` in
`01-protocol.md`. The cap is **256 bytes per label, enforced by the CLI at
attenuation time**, because labels are per-block free-form client text and the
depth cap × an unbounded label is an audit-log amplification with a perfectly
valid token (`07` §7). The cap binds only tokens this CLI produced, so the
supervisor also truncates labels at record time — a token from another minter
need not honor our cap, and the audit log's bounds cannot depend on good
behavior by its writers.

`ramenctl token inspect` prints the block chain: per block, its index, its
revocation id in hex, its checks, and its origin (root-signed, key-inherited,
or third-party — §2); and across the chain, the effective expiry and effective
prefix (below). This is the debugging tool you will use constantly in M9;
write it now.

**The token's effective authority is the intersection of its blocks, and the
CLI must report effective values — never only block-local ones.** Because the
parent's blocks remain in the child's token and every block's checks are
evaluated (§4), **a child can never outlive or outscope its parent**: the
parent's `date < PARENT_EXPIRY` check denies after that time regardless of
what the child's block says, and the effective expiry is the minimum across
all blocks — the same mechanism that makes prefix narrowing work. The emitted
checks must not try to re-express this (no `min(parent_expiry, now + N)`):
that duplicates enforcement into a place that does not enforce, and if chain
evaluation ever broke, you want that to fail loudly rather than be masked by a
redundant check.

The real gap is legibility, and it is a class of bug: **any place the CLI's
display of a token differs from its effective authority is a place a human
makes a wrong decision.** `attenuate --expires-in 15m` against a parent
expiring in two minutes would otherwise succeed silently, with `inspect`
showing the child's block saying 15m — and a human reading 15m is wrong. So:

- `inspect` reports the **effective** expiry (minimum across all blocks)
  alongside each block's own check.
- `attenuate` **warns** when the requested expiry exceeds the parent's
  effective expiry, and says what the effective value will be.

The same treatment generalizes to prefixes. A child restricted to `/a` under a
parent restricted to `/b` (no overlap) is a token that can never authorize
anything. `attenuate` **refuses** that outright — it is always a mistake, never
an intended configuration — and `inspect` shows the effective prefix as the
intersection of the blocks' prefixes.

`attenuate`, `inspect`, and `revoke` extend the `ramenctl` surface defined in
`06-ramenctl.md` with a `token` subcommand group.

## 4. Guard: evaluate the whole chain

The M4 guard verifies the root signature and evaluates the authority block.
M8 requires that every block's checks are evaluated and that a failure in any
block denies.

`biscuit-auth` does this correctly by default. The work here is not implementing
it — it is proving it, and handling what surrounds it.

**Block visibility.** A block's checks can see facts from the authority block,
from that block itself, and from the authorizer. They cannot see facts from
*later* blocks. This is what makes attenuation monotonic, and it means a child
cannot write a check that depends on a fact a grandchild will add. Write a test
that asserts this rather than assuming the library's behavior, because a change
here would silently widen every issued token.

**Depth cap.** Reject tokens with more than 16 blocks at `Hello` with
`TokenTooDeep`. Unbounded chain length is unbounded authorizer work on an
attacker-supplied input, and no legitimate delegation chain in Ramen is deep.

**Size cap.** Reject serialized tokens over 64 KiB at `Hello` with
`TokenTooLarge`, before parsing. This is a frame-level check.

**`describe_capabilities` must stop lying.** In M4 it summarizes the authority
block. Against an attenuated token that summary is wrong in the dangerous
direction: facts are present regardless of checks, so a fact-derived summary
over-advertises. M8 computes it by trial authorization: a fixed probe set —
one request per (operation, reversibility) pair the authority block grants —
is run against a fresh authorizer exactly as a real request would be.
FileWrite probes use the path `<prefix>/` for each authority `allowed_prefix`.
An operation is advertised only if **all** of its probes allow. A probe that
returns `Indeterminate` (an engine fault — §8, surface 2) counts as *not
allowed*: an operation whose probes cannot be evaluated is not advertised, the
same safe direction. For any token
with non-authority blocks, `Constraints` is `Unknown` (a new variant in
`ramen-proto`, lockstep with `05-operations.md`): a check can express
arbitrary path logic that no prefix list summarizes. Under-advertising is the
safe direction — an agent that does not see a capability can still attempt
the operation and get a precise denial; over-advertising is not. Whoami needs
no facts and is always summarized exactly. It is advisory in the protocol,
but an SDK will cache it and an agent will plan against it.

## 5. Revocation

The revocation id of block `i` is `hex(SHA-256(DOMAIN || L(content) ||
content || L(key) || key))`, where `DOMAIN` is the constant byte string
`ramen.revocation.v1` (domain separation — the id must not be confusable with
a value from another SHA-256 namespace in this tree, in particular the audit
chain hashes, which `02-audit.md` pins under `ramen.audit.genesis.v1`),
`content` is the block's raw datalog bytes as stored in the token's signed
envelope, `key` is the public key that signed the block (the root key for
block 0, block `i−1`'s `next_key` for `i ≥ 1`), and `L(·)` is a 4-byte
big-endian length prefix (it makes the concatenation split-unambiguous). One
function in `ramen-guard` (`Guard::revocation_id`) is the single source: the
guard's set membership, `ramenctl token inspect`, the revocation file, and the
audit `chain` all use it, so the four always agree. A test pins the domain tag:
the same inputs hashed without it produce a different value.

**The id is derived from content + signer, not from the signature bytes.**
ECDSA P-256 signatures are DER-encoded, and `(r, s)` / `(r, n−s)` are two valid
encodings of the same signature — the verifier does not enforce low-s under the
pinned biscuit-auth.

**Chain invariant (structural — this section relies on it).** In Biscuit v2
tokens, block *i*'s signature covers the serialized bytes of block *i−1*. It
follows that re-encoding any **non-terminal** block — P-256 high-s or any
other re-encoding — invalidates the whole token, and only the **last** block
of a token can be re-encoded undetected. This is a property of biscuit-auth's
chaining, not of this code. If a version bump changes the chaining, the test
`p256_high_s_reencoding_of_nonfinal_block_breaks_the_chain` fails, and the
revocation design must be re-examined before the bump is accepted — the test
is the tripwire, this paragraph is what its failure means.

Given that invariant, the last block of a token can be re-encoded into either
form at will: re-encoding it produces a token that verifies identically with
different signature bytes. A signature-derived id would stop matching after
such a re-encoding —
revocation would break exactly when it is being evaded. Content and signer key
are invariant under re-encoding. `ramen-guard` tests pin the three edges of
this: a high-s re-encoding of a P-256 signature still verifies and keeps the
id; an Ed25519 `s+L` re-encoding is rejected (dalek enforces canonical `s`);
re-encoding a non-final block breaks the chain, because the next block's
signature covered the original bytes. If a biscuit-auth bump starts
enforcing low-s (or accepts `s+L`), those tests fail and the derivation can be
re-examined — but the content+key form stays correct either way.

Because the id is a SHA-256 digest, every id is exactly 64 lowercase hex
characters regardless of block or algorithm. Nothing about the block (P-256 vs
Ed25519, signature length, position) is recoverable from its length — the
storage and audit formats below rely on that.

Revoking a block's id denies every token containing that block — which is the
block's own token and every token attenuated from it. One revocation kills a
subtree. This is the property that makes offline attenuation acceptable.

Because the id is derived from the grant, not the signing event, a re-issue of
the same grant (same content, same root) shares the id — the id names the
grant an identity issued, not the signing event. That semantics has two faces,
and both are accepted. The useful one: revoking a grant survives re-issuance —
re-minting cannot bring the grant back. The other face: two
tokens minted independently with identical content under the same root are
**indistinguishable in the audit log and share a revocation fate** —
revoking one revokes the other, and the log cannot say which of the two a
given decision was against. For Ramen's use the grant is the unit of identity;
per-signing-event identity is not needed. Do not "fix" this by adding a nonce
to the id: a nonce makes every token unique and silently destroys re-issue
stability — revocation would stop surviving re-mints, which is exactly the
regression the content+key derivation exists to prevent.

**Re-issue stability has a boundary, and it is the root key.** The
derivation includes the signer key, so re-issue stability holds *while the
root key is fixed*: rotate the root and the same grant text yields a
different id, and every entry in `revoked` goes stale **silently** — the
file still parses, the guard still checks it, nothing matches. That is a
**fail-open on rotation**: the revocation machinery keeps running while
protecting nothing, and no test or record flags it, because everything is
well-formed. Root rotation therefore requires re-deriving the revocation
file against the new key — recompute the ids of every grant still intended
to be revoked, atomically replace the file — and a rotation that does not do
this is a **security regression, not a housekeeping oversight**. Managed mode
makes rotation a real operation, so this is written down before it is needed:
the rotation procedure must carry revocation-file re-derivation as a step,
not a footnote.

### Storage

`$STATE_DIR/revoked` — newline-delimited. The legal line shapes are exactly
three: an **id** — exactly 64 lowercase hex characters and *nothing else on
the line* (no trailing comment, no surrounding whitespace); a **whole-line
comment** — first character `#`; and a **blank line**. Anything else is
malformed. Comments are whole-line only: `abc… # rotated out` is malformed,
and the rule above is the entire parser — one sentence, no precedence cases,
and the id case is trivially checkable (length 64, charset) because nothing
else can share the line.

- **Absent file → empty set.** First boot is not an error.
- **Present but malformed → refuse to start**, exit non-zero, log the line
  number and the line's shape (not its contents). A revocation list that
  fails open is worse than no revocation list, because someone will have
  relied on it.
- Reload on `SIGHUP` and on mtime change. A reload that finds a malformed
  line leaves the previous set in force and does not clear it — **and the
  failure must be as visible as the success**. A successful load audits
  `RevocationListLoaded` (record kind added to `02-audit.md` when this spec
  lands) carrying the count; a failed reload audits
  `RevocationReloadFailed` carrying the line number and the count that
  remains in force. The reason for the symmetry: a failed reload keeps the
  stale revocations (good) and **silently drops the new ones in that
  file** (bad) — an operator who appended an id and typoed a different line
  believes the revocation landed. The record is what tells them it did not;
a log line alone is not enough, because logs are ephemeral and the audit
  is the artifact an operator checks after an incident.

### Guard interface

The guard does no I/O (`04-guard.md`). The set is injected, and the id is a
**newtype, not a `&str`**:

```rust
/// A revocation id: exactly 64 lowercase hex characters. The only
/// constructors are `new` (the validation) and `Guard::revocation_id`
/// (which always produces a valid digest). There is no other path to this
/// type.
pub struct RevocationId(/* 32 bytes */);

impl RevocationId {
    /// `None` unless `hex` is exactly 64 lowercase hex characters.
    pub fn new(hex: &str) -> Option<Self>;
}

pub trait RevocationSet: Send + Sync {
    /// One representation end to end, enforced by the type: a caller
    /// cannot pass an uppercase or malformed id, because there is no
    /// `&str` to pass.
    fn is_revoked(&self, id: &RevocationId) -> bool;
}
```

A `&str` interface invites the exact bug this section's argument forbids:
the file is specified lowercase, but nothing stops a caller from some other
path passing uppercase and getting a **silent miss** — a revocation that
looks checked and isn't. The newtype makes "one representation end to end"
a type-level property instead of a comment asserting it: the file parser,
`Guard::revocation_id`, the set's membership, and `ramenctl` all speak
`RevocationId`, and the only ways to build one are the validating
constructor and the guard's digest.

Checked **before** authorizer construction, for every block id in the token, not
just the terminal one — revoking the authority block's id revokes every token
the root signed, the whole tree. Denial code `TokenRevoked`. The check is a set
membership test per block, bounded by the depth cap from §4.

### `ramenctl token revoke`

Takes a revocation id, or a token file plus `--block N` (defaulting to the
terminal block), in which case the id is computed with `Guard::revocation_id`
using the root public key from the supervisor config's `root_key_path` — the
same key the guard verifies with, so the tool can never compute an id the
guard would not. Appends to the file, signals the supervisor. Appending must be
atomic — write to a temp file in the same directory and rename.

**The command then verifies its own append**: it re-reads the file, parses it
with the §5 rules, and checks the id is present — exiting non-zero if it is
not, rather than assuming the signal worked. The division of responsibility
is the point: the command confirms the *file* took the write; the
supervisor's `RevocationListLoaded` / `RevocationReloadFailed` record
confirms the *set* took the file. Between the two, an operator gets a
complete answer to "is this revocation in force?" — and a failure at either
half is actionable instead of presumed.

Revocation is append-only in v0. Un-revoking means editing the file by hand,
which is the correct amount of friction.

## 6. Expiry and the clock

`04-guard.md` §4 already injects the clock fact (and §8 covers the clock
itself). Two requirements become load-bearing once tokens carry expiry:

- The clock fact (named in `04-guard.md` §4 — this spec does not restate the
  name in prose, so the two documents cannot drift) comes from the
  supervisor's clock. There is no path by which a client-supplied value
  reaches it. The property — "no client-supplied value reaches the fact" —
  is not something a grep can express directly; what it *can* express is the
  sufficient condition: **the fact's construction is the only place the
  fact's name is written, and the construction takes its input from the
  injected `now`.** The CI job is therefore concrete, not aspirational:
  grep `ramen-guard/src` for the fact's literal (the `date` fact as named in
  `04-guard.md` §4) and assert that every occurrence is a fact-construction
  call whose value argument is the request's injected `now` (today: the
  `date(...)` facts built from `req.now` in `authorize` and its probe
  authorizer). A new occurrence with any other argument — a live
  `SystemTime::now()` call, a client field, a constant — fails CI. Note the
  join property: if §4's name ever changes, the code change breaks the
  grep, which forces the spec, the code, and the job to move together
  instead of silently decoupling.
- Wall clock, not monotonic. A token expiring at an absolute time cannot be
  evaluated against uptime.

Denial code `TokenExpired`, distinct from a general check failure, because
"retry with a fresh token" and "you never had this capability" are different
instructions to an agent and it will act on the difference.

**The rule:** a token is valid while `now < expiry`, and denied at
`now == expiry`. The clock fact is integer seconds, so granularity is 1
second, not 1 ns — a boundary test finer than that cannot be expressed in
the token. The tests pin the rule on both sides as assertions, not as an
agreement: at `t == expiry` the token is denied with `TokenExpired`; at
`t == expiry − 1s` it is allowed. Biscuit's `<` is strict, so the emitted
check (`$t < EXPIRY`) implements the rule as stated — and the tests are
what keeps it true across biscuit bumps: a bump that changes comparison
semantics fails both boundary tests, and failing either means the rule
above, not the test, is what is wrong.

**Single-host assumption (deferred to managed mode).** v0 resolves expiry on
the attenuating machine's clock and enforces it on the supervisor's clock; on
one host these are the same clock. In managed mode (attenuator and supervisor
on different machines), skew means a token can be born already expired
(attenuator clock fast) or outlive its intended lifetime (attenuator clock
slow). **The two skews are not symmetric, and the obvious knob trades in the
wrong direction.** Born-already-expired is a denial: an annoyance, the agent
re-mints. Outliving the intended lifetime is a *security failure*: the token
keeps working after the grant was meant to end. A mint-time margin (padding
the expiry so a slow attenuator doesn't birth dead tokens) fixes the first
and **makes the second worse** — it extends every token's real lifetime by
the margin. One-sidedness of v0's own rounding, stated here because this is
where margin-reasoning happens: §3 floors `EXPIRY` to `floor(now, 1s) + N`,
so on the minting host a token is never valid for *more* than N — v0 already
leans the safe way. The margin therefore has no "compensate for the floor"
role to play; it is pure lifetime extension, which is exactly why it trades
in the wrong direction. Whoever picks this up should start from the
asymmetry: the safe skew is the one that denies early, and the design question
is how to tolerate the denying skew without buying the other one. Managed-mode
work must define the clock-trust rule where `04-guard.md` §8 already points:
the skew bound and mint-time margin for attenuated tokens belong alongside the
Roughtime note there, not in this document.

## 7. Audit: identity is the chain, not the name

Every record of a completed decision — `Authorized`, `Denied`, and
`Indeterminate` — carries:

```rust
pub struct TokenIdentity {
    /// From the authority block. Stable across attenuation.
    pub identity: String,
    /// One revocation id (§5) per block, root-first. Length = chain depth.
    pub chain: Vec<String>,
    /// Labels from attenuation blocks, in order. Never authoritative.
    /// Truncated to the §3 cap at record time.
    pub labels: Vec<String>,
}
```

Recording only `identity` would make every descendant of `agent:planner` look
like `agent:planner` in the log, which defeats the purpose of the log at exactly
the moment it starts to matter. The chain is what distinguishes them, and it is
also what you revoke on, so the log tells you the revocation id to act on
without needing the token in hand.

`Indeterminate` records carry this **not merely by following from the word
"decision"** — it is load-bearing on its own. The operational signal for
indeterminates is distinguishing one pathological client from system-wide load
(`02-audit.md`), and the chain is exactly the field that answers it: a burst
clustering on one chain is one client, a burst spread across many chains is
the machine. Every `Indeterminate` record has a **verified** chain — the
guard reaches evaluation only after root re-verification, so every id in it is
one an operator can act on. (The untrusted-chain case — a signature failure —
never produces an `Indeterminate`; it produces the record below with `chain`
absent.)

Two new record types:

- `RevocationListLoaded { count, sha256 }` at startup and on every reload. The
  set of tokens the supervisor considers valid is part of the security state of
  the system; a change to it belongs in the chain. `sha256` is over the file's
  byte content (not the parsed set), so the audit trail detects any
  byte-level change to the file between load and audit — **under the domain
  tag `ramen.revocation.file.v1`**, the same convention as the audit genesis
  (`ramen.audit.genesis.v1`) and the revocation ids (`ramen.revocation.v1`):
  no bare SHA-256 value in this tree, so a file digest can never be confusable
  with an id, a chain hash, or any other digest.
- `TokenPreAuthRejected { reason, chain: Option<Vec<String>> }` for rejections
  that happen before authorization — depth, size, signature, revocation. The
  name is for the **phase**, and it is deliberately distinct from the denial
  code `TokenRejected`: that one is already in the wire's closed
  `deny_unknown_fields` enum, where renaming it is a protocol change, and it
  means "the engine surfaced a token-derived fault during evaluation." The two
  must never be plausibly confusable in a log line, because the operator's
  response differs: this record says the token was rejected **before any
  policy ran**; the code says the machine ran the policy and the token failed
  inside it.

  `chain` is present only when **every** signature in the chain has verified —
  i.e., only when every id is one an operator can act on. It is absent for
  `TokenTooLarge`, because the size cap rejects before any parsing and there
  is no block to name. It is also **absent for signature failures**: a token
  whose authority block fails signature verification has a chain that is
  extractable syntactically but untrustable semantically — the ids are derived
  from content and a key that did not sign it. That is not nothing, but it
  must not sit in the same field as an id you would act on: an operator who
  pastes an untrusted id into `revoked` is a small footgun. Omit the chain,
  and record the failing block's position in `reason`.

These are distinct from `Denied`, which means the token was structurally fine
and policy said no.

Bounds: where present, chain fields are bounded by §4's depth cap, and each id
is the fixed 64-character form of §5. Labels are bounded separately, and the
bound lives in two places on purpose (§3): the minter caps each label at
**256 bytes at attenuation time**, and the supervisor **truncates at record
time**. The minter cap only binds tokens this CLI produced — a token from
another minter need not honor it, and per-block free-form labels × the depth
cap is an audit-log amplification attack with a *valid* token. With both
bounds, no record can be inflated by an attacker-supplied token. Verify
that: the flood test in `03-supervisor.md` should be re-run with
maximum-depth tokens carrying maximum-size labels.

## 8. Denial codes

M8 adds five codes to the closed set in `01-protocol.md` §4 (proto enum and
spec change land in the same commit):

| Code | Meaning | New in M8 |
|---|---|---|
| `TokenRevoked` | Some block in the chain is in the revocation set. | yes |
| `TokenTooDeep` | Block count over cap. | yes |
| `TokenTooLarge` | Serialized size over cap. | yes |
| `AttenuationDenied` | A check in a non-authority block (N > 0) failed. | yes |
| `TokenRejected` | The engine surfaced a token-derived fault — format, base64, language, conversion, an unevaluatable expression in the token's own checks, **or a block that fails signature verification** (a tampered token — surface 2 below, `04-guard.md` §5). | yes |
| `TokenExpired` | A time check failed. | no — existing (M4) |
| `CapabilityNotGranted` | The authority block never granted this operation. | no — existing (M4; this is the `CapabilityAbsent` of early drafts) |
| `ReversibilityNotPermitted`, `ConstraintViolated`, `ControlPlaneProtected` | As in `04-guard.md`. | no |

**Classification on the denial path — an ordered decision list** (replaces
the probe list in `04-guard.md` §5; `04` is updated in the same commit as the
`classify()` change):

```
1. Whole-token re-run with the far-past clock (04 §5 step 3) allows
   → TokenExpired.
2. authorize() reports a failed check in block 0 (authority)
   → ConstraintViolated.
3. authorize() reports a failed check in block N > 0
   → AttenuationDenied (earliest such block; its id goes in reason).
4. No capability($op) fact for the requested operation
   → CapabilityNotGranted.
5. No reversibility_allowed($r) fact for the requested r
   → ReversibilityNotPermitted.
6. Otherwise → ConstraintViolated (fail closed).
```

The list is disjoint by construction: a policy deny from missing facts
produces **no** failed check, so rules 2–3 never compete with rules 4–5; any
failed check is one of the token's own `check` clauses. Biscuit reports the
failing block id directly (`FailedBlockCheck { block_id, .. }`), so the
classification names which block a human should look at.

Denials come from **three surfaces**, and the ordered list is one of them:

1. **Pre-evaluation rejection** — the token is rejected before any policy runs:
   `TokenTooLarge` (size), `TokenTooDeep` (depth), `TokenRevoked` (revocation).
   Each carries the `TokenPreAuthRejected` record (§7); `chain` presence
   follows §7's rule (present only when every signature in the chain has
   verified).
2. **Engine fault** — `TokenRejected`: the engine surfaced a token-derived
   error rather than a failed check — format, base64, language, conversion, an
   unevaluatable expression in the token's own checks, **or a block that fails
   signature verification** (a tampered token). A tampered or corrupted token
   must **never** produce `Indeterminate`: it is deterministic and
   attacker-supplied, and classifying it as a machine fault would let an
   attacker poison the signal that a burst of indeterminates means resource
   pressure or a pathological token. It carries the `TokenPreAuthRejected`
   record with `chain` **absent** — a chain that fails verification is not
   actionable (§7).
3. **Classified denial from a completed evaluation** — the ordered list above
   (rules 1–6), where one of the token's own checks failed.

The list is not the whole denial surface, and none of the codes of surfaces
1–2 is ever produced by it. When a code is added in the future, the first
question is which of the three surfaces it belongs to.

`AttenuationDenied` and `CapabilityNotGranted` must be distinguishable. An
agent denied by its own attenuation should ask its parent for a wider grant;
an agent denied by the authority block should stop. Collapsing these produces
retry loops.

Two notes:

- **This reorders the existing probes.** The current `classify()` checks
  capability and reversibility before the time probe; this list moves the
  time probe first. Note what reordering does and does not change: a token
  that is *both* expired and capability-less reports
  `CapabilityNotGranted`, **not** `TokenExpired` — the far-past re-run of
  rule 1 still denies a capability-less token, because the missing fact is
  not time-dependent, so rule 1 never fires and the list falls through to
  rule 4. That is the better answer anyway: it tells the agent the terminal
  problem instead of the transient one — re-minting with a fresh expiry would
  not have helped.
- **The time probe inverts for activation windows.** It identifies denials by
  "valid until" checks (`date($t) < EXPIRY`). A "valid from" check
  (`date($t) > START`) also denies at the far-past probe, so a not-yet-valid
  token is classified by rules 2/3, not `TokenExpired`. v0 mints no
  activation windows (`ramen-mint` has no such flag); if one is added, this
  rule is re-examined.

This does disclose *where* in the chain the denial occurred. That is
acceptable: the caller holds the token and can read its own blocks. Do not
include the failing check's text — that is the authority block's business
and the caller may not have written it.

## 9. What must not happen

Anti-goals, stated because each is a plausible-looking simplification:

- **No fact-granting blocks.** If a code path ever lets a non-authority block
  add a `capability()` or `allowed_prefix()` fact, attenuation stops being
  monotonic and the entire model is void. Test that a hand-crafted token with a
  `capability()` fact in block 1 does not gain that capability.
- **No signature-derived authority.** The peer's code signing identity is still
  recorded, never an authorizer fact (`04-guard.md` §4). Delegation does not
  change this.
- **No caching of authorization decisions across requests.** Fresh authorizer
  per request, still. A cache keyed on token would be wrong the moment a
  revocation lands.
- **No implicit re-minting.** A supervisor that notices an expired token and
  issues a fresh one has become a minting oracle. Expired means denied.

## 10. Acceptance criteria

All of the following are tested. Several are regressions over existing M4
behavior (fact-invisibility, monotonicity, the far-past clock probe) rather
than new work; they exist so a biscuit-auth bump that silently changes any of
them fails loudly.

- [ ] Attenuated token writes inside its narrowed prefix; denied outside it but
      inside the parent's prefix, with code `AttenuationDenied`.
- [ ] Same token denied for an operation the authority block never granted, with
      code `CapabilityNotGranted`. The two codes are asserted distinct in one test.
- [ ] Attenuating with a *wider* prefix than the parent's yields a token that is
      still bounded by the parent's prefix. Checks intersect; they do not
      replace.
- [ ] Hand-edited token with one byte flipped in an attenuation block fails
      signature verification: code `TokenRejected` (surface 2),
      `TokenPreAuthRejected` record with `chain` absent — never `Denied`, and
      **never `Indeterminate`** (a corrupted token is deterministic and
      attacker-supplied; it must not be able to feed the Indeterminate signal).
- [ ] Hand-crafted token with a `capability()` fact in a non-authority block
      does not gain that capability.
- [ ] A block's check referencing a fact defined in a later block does not
      match. Asserted directly, not inferred.
- [ ] Revoking the *parent's* block id denies a child token that authorized
      successfully one second earlier, without restarting the supervisor.
- [ ] Revoking a child's terminal block id leaves the parent token working.
- [ ] Malformed `revoked` file (a line that is not a comment or exactly 64
      lowercase hex characters) → supervisor refuses to start. Malformed file
      on reload → previous set still enforced, error logged, no requests
      authorized against an empty set.
- [ ] A token minted by `ramen-mint --expires` is allowed before its expiry and
      denied `TokenExpired` after it — the minted check must resolve against the
      guard's clock fact (`04-guard.md` §4). The regression pin for the
      `time`/`date` drift.
- [ ] The revocation id derivation is pinned against re-encoding: a P-256
      high-s re-encoding of the last block still verifies and keeps the id;
      Ed25519 `s+L` is rejected; re-encoding a non-final block breaks the chain.
      Every id is exactly 64 lowercase hex characters, for every block. The
      id is domain-separated (`ramen.revocation.v1`): the same inputs hashed
      without the tag produce a different value.
- [ ] Token expired by 1 **second** (the clock's granularity) is denied with
      `TokenExpired`; valid 1 second before expiry is allowed.
- [ ] 17-block token rejected with `TokenTooDeep` before any Datalog evaluation
      runs. Assert by instrumenting the authorizer, not by timing.
- [ ] Every `Decision` record for a **parsed** token carries a `chain` whose
      length equals the token's block count, and whose terminal entry matches
      `ramenctl token inspect --block -1`; `TokenTooLarge` records carry no chain.
- [ ] `ramen-audit-verify` exits 0 after a full M8 test run, including the runs
      that use malformed tokens. **Same assertion as M7 §6:** hostile input must
      not be able to corrupt the chain.
- [ ] `describe_capabilities` against an attenuated token does not report a
      capability that a real request would be denied.

## 11. What M8 completes, and what M9 needs from it

After M8 the capability model is load-bearing rather than illustrative: a token
can be narrowed by its holder, the narrowing is enforced, and a subtree can be
killed. Nothing in the system yet *produces* a delegated token automatically —
that is the point of M9.

`ProcSpawn` will need exactly five things from this milestone, and if any of
them is shaky it will show up as a security bug rather than a test failure:

1. Attenuation as a library call, not just a CLI path. Factor the block
   construction in §3 into `ramen-guard` (or a `ramen-token` crate) so the
   supervisor can call it during spawn. The CLI becomes a thin caller.
2. The child's terminal-block revocation id, computed with
   `Guard::revocation_id` (§5 — content + signer key, stable under signature
   re-encoding and across re-issue), available to the spawner at spawn time,
   so the audit record for the spawn names the child token it created, and so
   killing the child's subtree is a one-liner.
3. Expiry with short defaults that actually work. A spawned child's token should
   outlive the process by minutes, not days, and §6's boundary behavior is what
   makes a short expiry safe to rely on. A leaked token file is also a leaked
   delegable key (§2), so a short expiry independently bounds that damage
   window.
4. An `Indeterminate` on a spawned child's token must be distinguishable and
   handled correctly: the child retries with backoff (the `01-protocol.md`
   guidance); it does not re-mint — re-minting on `Indeterminate` burns the
   parent's grants on a transient machine condition, and `Indeterminate` must
   stay distinguishable from `Denied` on the wire so that the two responses
   keep their distinct instructions. The `chain` field on the `Indeterminate`
   record (§7) is what makes the operator-side question answerable: a burst
   clustering on the spawn-produced chain is one child; spread across many
   chains, it is the host.
5. Spawn-time attenuation must respect §3's effective-authority rule
   **programmatically**: the child's expiry is bounded by the parent's
   *effective* expiry (the minimum across the parent's blocks, not the
   parent's own block's check), and the CLI's warn/refuse behaviors (§3) are
   what the library call from item 1 enforces for the supervisor.

Re-read `00-overview.md` §"Non-negotiable invariants" before starting M9.
Invariant 1 is the one `ProcSpawn` is most able to violate, and it will not
violate it loudly.