# 02 — `ramen-audit`

Milestone M2. Append-only log with hash chaining, a group-commit writer, and a
standalone verifier.

Built before the supervisor deliberately. An audit log added after the fact
ends up with gaps, because the code paths that should have written records were
written without one available.

Dependencies: `serde`, `serde_json`, `sha2`, `thiserror`, and `tokio` with the
`sync` feature only (mpsc / oneshot for the group-commit writer — no runtime
features in this crate). The log's *guarantee* is synchronous durability; the
*implementation* is a dedicated blocking writer thread (§5).

## 1. What this is not

`ramen-audit` is not logging. `tracing` output is for operators debugging the
supervisor; it is unstructured, lossy, sampled, and may be disabled. The audit
log is a tamper-evident record of authorization decisions and effects. Never
route one through the other, and never let a `tracing` failure affect an audit
write or vice versa.

## 2. Storage format

One file. Append-only. Each record is a framed line:

```
+--------+------------------------+
| u32 BE | canonical record bytes |
+--------+------------------------+
```

Same framing as the wire protocol, reused so there is one framing
implementation to get right. The audit crate may depend on `ramen-proto`'s codec
for this, or duplicate ~30 lines to keep the dependency graph flat. Either is
fine; pick one and note it in the module docs.

## 3. The chain

```
record_hash[n] = SHA-256( record_hash[n-1] || frame_bytes[n] )
record_hash[-1] = SHA-256( GENESIS_DOMAIN || log_id )
```

where `frame_bytes[n]` is the **exact byte sequence written to disk**,
length prefix included.

Hashing the bytes as written, rather than a re-serialization of the parsed
record, removes canonicalization entirely from the threat model. JSON is not
canonical — key order, whitespace, and number formatting all vary — and a
verifier that re-serializes before hashing will eventually disagree with the
writer over something cosmetic. Hash what is on disk.

`GENESIS_DOMAIN = b"ramen.audit.genesis.v1"`. The domain separator prevents a
genesis hash from being confused with an interior chain hash. `log_id` is a ULID
generated when the log is created and stored in the header record (§4).

`prev_hash` is carried **inside** each record as a hex string, so the chain is
verifiable from the file alone with no side state. This is redundant with
recomputation, which is the point: a verifier can check both that the stated
`prev_hash` matches the recomputed one and that the sequence is unbroken.

## 4. Record schema

Record 0 of every log is a header:

```json
{
  "seq": 0,
  "kind": "LogHeader",
  "log_id": "01J8Z...",
  "created_at": "2026-08-30T14:02:11.482Z",
  "prev_hash": "<genesis hash, hex>",
  "supervisor_version": "0.1.0"
}
```

All subsequent records:

```json
{
  "seq": 1041,
  "ts": "2026-08-30T14:07:33.119Z",
  "prev_hash": "9f2c...",
  "session": "01J8Z...",
  "identity": "agent:planner",
  "peer": {
    "pid": 48213,
    "signing_id": "com.example.planner",
    "cdhash": "a3f1...",
    "verified": true
  },
  "request_id": "01J8ZQ...",
  "op_type": "FileWrite",
  "reversibility": "Trivial",
  "kind": "Authorized",
  "detail": { ... }
}
```

`kind` is a closed set:

| Kind | Written when |
|---|---|
| `LogHeader` | Log creation. Always `seq` 0. |
| `SessionOpened` | Handshake succeeded. Carries the `client` metadata from `Hello` (below). |
| `SessionClosed` | Connection ended, with reason. |
| `IdentityRejected` | Peer identity could not be verified. No session exists yet. |
| `Authorized` | Guard permitted. Written **before** any effect, including the snapshot. |
| `Denied` | Guard refused. Carries the denial code. |
| `Errored` | A non-fatal `Error` response was sent to the client (e.g., `NotImplemented` in M3). |
| `Executed` | Effect completed. Carries outcome and any restore handle. |
| `ExecutionFailed` | Effect attempted and failed. |
| `ProtocolViolation` | Fatal framing or envelope violation; the connection was closed. |
| `TailTruncated` | `open` recovered a partial trailing frame (§6). Carries the discarded byte count and the SHA-256 of the discarded bytes. |

Note that an authorized operation produces **two** records: `Authorized` before
any effect, `Executed` or `ExecutionFailed` after. This is what makes invariant
2 checkable — an `Authorized` with no following terminal record is a crash
window, and it is visible. This holds for all operation types, mutating or not
(see `05-operations.md`, M5).

`peer.verified` must be `true` for any `Authorized` record. A verifier that
finds otherwise reports a critical finding.

**Handshake metadata.** The `client` field from `Hello` (`01-protocol.md` §5)
is advisory and is recorded **only on the `SessionOpened` record**:
`{ "name": ..., "version": ..., "truncated": false }`. It is handshake-scoped,
so it does not belong on every record. It never influences authorization
(`04-guard.md` §4).

### What must not be in `detail`

`detail` never contains file contents, token bytes, key material, or
environment values. It contains references: paths, byte counts, content hashes.

An audit log is read by more people, and stored in more places, than the data it
describes. A log that inlines the contents of every written file is a
higher-value target than the files. Record `sha256` of content when integrity
matters; never the content.

## 5. Write discipline

```rust
pub struct AuditLog { /* ... */ }

impl AuditLog {
    /// Opens existing or creates. Verifies the full chain and recovers the
    /// tail. Refuses to open a chain-invalid log. A partial trailing frame
    /// (crash mid-write) is recovered per §6.
    pub fn open(path: &Path) -> Result<Self, AuditError>;

    /// Appends, and returns the assigned sequence number only after the record
    /// is durable (fsync + F_FULLFSYNC). `&self`: the append is dispatched to
    /// the log's dedicated writer thread.
    pub async fn append(&self, record: &Record) -> Result<u64, AuditError>;
}
```

**Group commit.** `append` sends the record over an mpsc channel to a dedicated
blocking writer thread and awaits a oneshot. The writer drains the queue,
writes all pending frames, issues **one** `F_FULLFSYNC`, and then replies to
every waiter. Each waiter still observes durability-before-return; the flush
cost amortizes across the burst instead of serializing on the async runtime's
worker threads. This is the standard group-commit pattern, and it is why
`append` is `async` while the guarantee is synchronous: the original
"synchronous and blocking" framing was right about the guarantee and wrong
about the implementation.

Durability means `File::sync_all()` (which issues `fsync`) **and**, on macOS,
`F_FULLFSYNC` via `fcntl` — `fsync` on macOS does not guarantee the drive has
flushed its write cache, and without `F_FULLFSYNC` a power loss can lose
records that `fsync` reported as durable. The `unsafe` needed for `F_FULLFSYNC`
is confined to a single module.

If `append` fails for any reason, the supervisor **refuses service** — it does
not proceed with the operation and does not continue in a degraded mode
(invariant 4). Surface as `Error/AuditUnavailable` and close the connection.

`append` assigns `seq` and computes `prev_hash` itself. Callers must not supply
either; make them non-constructible from outside by taking a
`Record`-without-chain-fields input type and adding them internally.

**Single writer.** Exactly one `AuditLog` handle exists per process and per
file. Do not implement multi-process append. Take an advisory `flock(LOCK_EX)`
on open and fail if it is held — two supervisors appending to one chain produce
an interleaving that is not recoverable.

**Shutdown.** The writer queue is drained before the log is closed
(`03-supervisor.md` §3). A record in the queue at shutdown is a recorded
decision that must survive.

## 6. Tail recovery

On `open`, if the file ends in a partial frame — a length prefix or body cut
short by a crash mid-write:

1. Truncate the file to the end of the last valid frame.
2. Append a `TailTruncated` record: the discarded byte count and the SHA-256 of
   the discarded bytes.

The mutation of the audited artifact becomes itself an audited act with evidence
of what was destroyed. The verifier reports `TailTruncated` as a warning, not a
failure.

**Clean truncation is undetectable.** Removing whole frames from the tail
leaves a chain that is internally consistent: the sequence runs contiguously to
the truncated end, and every stated `prev_hash` matches. Detecting this
properly requires an external anchor — a periodically published head hash. That
is out of scope for v0; it is documented as a known gap in the module docs, and
the acceptance criteria below pin the current behavior so the gap is never
accidentally "fixed" into a false sense of security.

## 7. Rotation

Not in v0. The log grows without bound. Do not implement rotation, compaction,
or truncation.

Rotation is a chain-continuity problem — the new file's genesis must commit to
the old file's final hash, and the linkage must itself be tamper-evident — and
getting it wrong silently breaks the property the log exists to provide. Grow
the file until there is real pressure, then design it properly.

## 8. Verifier

Ship `ramen-audit-verify` as a binary in this crate. It must run with no access
to the supervisor, its keys, or its configuration — a verifier that needs the
thing it is auditing is not much of a verifier.

```
ramen-audit-verify <path> [--json] [--from SEQ] [--to SEQ]
```

Checks, in order:

1. Record 0 is a well-formed `LogHeader`.
2. Genesis hash matches `SHA-256(GENESIS_DOMAIN || log_id)`.
3. `seq` increments by exactly 1 with no gaps.
4. Each record's stated `prev_hash` equals the recomputed hash of the previous
   frame.
5. Timestamps are non-decreasing. A decrease is a **warning**, not a failure —
   clock adjustment is real and does not by itself imply tampering. Report it.
6. Every `Authorized` record has `peer.verified == true`. Violation is critical.
7. Every `Authorized` record — **all operation types; the verifier has no
   mutability knowledge** — is followed by `Executed` or `ExecutionFailed` for
   the same `request_id`. An unmatched one at the tail is a crash window
   (warning); one in the interior is critical.
8. The final frame is complete. A partial trailing frame means a crash
   mid-write: report a truncation warning with the last valid `seq`. A
   `TailTruncated` record means recovery occurred (§6): warning.

Exit codes: `0` clean, `1` warnings only, `2` verification failed, `3` file
unreadable. Distinct codes matter because this will be run from a cron job or a
CI check where "failed" and "could not run" need different responses.

Note: a cleanly truncated tail (whole frames removed) passes checks 1–4 locally
and is undetectable in v0 — known gap, §6.

## 9. Acceptance criteria (M2)

- [ ] `cargo test -p ramen-audit` passes; `#![forbid(unsafe_code)]` except the
      `F_FULLFSYNC` module.
- [ ] Append 10,000 records; verifier exits 0.
- [ ] Flip one byte in a record body mid-file; verifier exits 2 and names the
      first bad `seq`.
- [ ] Delete a record from the middle; verifier exits 2 on the sequence gap.
- [ ] Reorder two adjacent records; verifier exits 2.
- [ ] Truncate the file mid-frame; verifier exits 1 and reports the last valid
      `seq`. `AuditLog::open` recovers: the file is truncated to the last valid
      frame and a `TailTruncated` record is appended; re-verification exits 1
      (warning) with a valid chain.
- [ ] Truncate the file at a frame boundary, removing whole frames from the
      tail: **undetectable in v0** (no external anchor). The test documents
      current behavior — verifier exits 0 — and asserts the known-gap note
      exists in the module docs.
- [ ] `append` returns only after `F_FULLFSYNC`; a burst of concurrent appends
      produces one `F_FULLFSYNC` per drain cycle (group commit). Assert by
      inspection and note it in a test comment; this is not directly observable
      from a unit test.
- [ ] Second `AuditLog::open` on the same path fails while the first is held.
- [ ] `open` on an interior chain-invalid file returns `Err`, never a usable
      handle.
- [ ] Grep the crate for content-bearing fields in `detail` — no test can prove
      this, so it is a review checklist item.
