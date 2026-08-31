# 05 — Operations

Milestones M5 (`Whoami`) and M6 (`FileWrite`).

Two operations only. The purpose of v0 is a correct vertical slice, and each
additional operation multiplies the surface that must be reviewed without
testing anything the first two do not.

## M5 — `Whoami`

### Why this operation first

`Whoami` has no side effects. It exercises the socket, framing, peer identity,
token verification, authorizer construction, and audit append end to end. When
it breaks, the failure is in one of those layers and not in an effect.

An operation that both proves the pipeline and cannot damage anything is worth
having as the first one even though it is not independently useful.

### Request

```json
{ "v": 1, "id": "01J8ZQ...", "op": { "type": "Whoami" } }
```

No parameters. `Reversibility::Trivial`.

### Response

```json
{
  "v": 1,
  "id": "01J8ZQ...",
  "status": "Ok",
  "result": {
    "identity": "agent:planner",
    "session": "01J8Z...",
    "capabilities": [
      { "op": "Whoami",    "reversibility": "Trivial" },
      { "op": "FileWrite", "reversibility": "Trivial",
        "constraints": { "path_prefix": ["/Users/austin/work"] } }
    ],
    "token_expires_at": "2026-08-31T00:00:00Z"
  }
}
```

`token_expires_at` is `Option`: `null` when the token carries no
`expires_at` fact (`04-guard.md` §1). It is advisory metadata only — it does
not affect authorization. The token's time check is authoritative, and if the
fact and the check disagree, the check wins.

This is the guard's view of the token, recomputed at call time — not the cached
`Welcome` summary. Recomputing matters: it means `Whoami` reflects the authorizer
as it currently evaluates, which is what makes it useful for debugging a denial.

The capability list is a **summary of the token's facts** (the `capability`,
`allowed_prefix`, and `reversibility_allowed` predicates), not a re-evaluation
of the full policy for a hypothetical request. It answers "what does this token
claim to grant," for humans and debug tools. The authoritative answer to "may
this caller do X" is the per-request decision from `authorize`, and the two are
computed separately: a policy change could make them disagree, and that is by
design. The list must never be treated as a promise.

`Whoami` reports **only** the caller's own token. It exposes nothing about the
supervisor's configuration, other sessions, the root key, or the audit log.
Introspection endpoints are a common route to leaking the enforcement boundary's
shape; keep this one narrow.

### Audit

`Authorized` then `Executed`. A non-mutating operation still gets both records,
so the audit invariant in `02-audit.md` §8 (check 7) is uniform across all
operation types rather than conditional on mutation.

### Acceptance criteria (M5)

- [ ] Authorized `Whoami` returns identity, session, and capabilities.
- [ ] Token without `capability("Whoami")` → `Denied/CapabilityNotGranted`.
- [ ] Result reflects the live guard evaluation: mint a token, connect, and
      assert that the `Whoami` capability list matches a direct call to
      `describe_capabilities`.
- [ ] Audit shows `Authorized` then `Executed`, both with the same
      `request_id`, in that order, with no gap in `seq`.
- [ ] Result contains no path outside what the token grants, and no
      supervisor configuration values. Review checklist item.
- [ ] Three concurrent `Whoami` requests on one connection all return, with
      responses correctly matched to request ids. Delay one artificially so
      responses arrive out of order and assert the client still matches them.

## M6 — `FileWrite`

### Why this operation second

It is the first operation with real reversibility semantics, and it forces
`clonefile(2)` and the restore-handle model into the design while there is only
one caller to adapt. Deferring the reversibility mechanism until several
mutating operations exist means retrofitting it into all of them.

### Request

```json
{
  "v": 1,
  "id": "01J8ZQ...",
  "op": {
    "type": "FileWrite",
    "path": "/Users/austin/work/notes.md",
    "content_b64": "SGVsbG8sIHdvcmxkLgo=",
    "mode": "Overwrite"
  }
}
```

```rust
pub struct FileWriteOp {
    pub path: PathBuf,
    pub content_b64: String,
    pub mode: WriteMode,
}

pub enum WriteMode { Create, Overwrite }
```

`Create` fails if the path exists. `Overwrite` requires the path to exist. There
is no create-or-overwrite mode: the caller must state which it expects, so that
a wrong assumption surfaces as an error rather than as silent data loss.

Content is base64 in JSON. Cap decoded size at 256 KiB, well under the 1 MiB
frame limit. Large-file writes need a streaming operation, which is not v0.

### Reversibility

`Reversibility::Trivial` — but only because of the snapshot, and only for
`Overwrite`.

| Mode | Class | Compensation |
|---|---|---|
| `Overwrite` | `Trivial` | `clonefile` snapshot taken before the write |
| `Create` | `Trivial` | unlink the created file |

Both are `Trivial` because both are undoable by a local, cheap, deterministic
operation requiring no external coordination. If the snapshot cannot be taken,
the operation is **not** `Trivial` — and rather than silently reclassifying, the
supervisor fails the operation (§ below). Reclassifying at runtime would break
the static-classification property in `01-protocol.md` §6 and, worse, would mean
a token authorized for `Trivial` operations could cause an unsnapshotted write.

### Execution sequence

Order is load-bearing. Do not rearrange for convenience.

1. Guard authorizes. Path is canonicalized during authorization
   (`04-guard.md` §6), including the final-component symlink check. **Use the
   canonicalized path from here on**; the client-supplied string is not
   referenced again.
2. Decode base64. Check the 256 KiB cap. Failure → `Error/MalformedRequest`,
   no audit `Authorized` record. Decode before the authorized record so a
   malformed request does not produce a recorded intent that never had a chance
   of executing.
3. **Pin the target's parent directory**: open the canonical parent with
   `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` and verify the opened descriptor *is*
   that directory — a stat before and after the open must agree on device +
   inode, and the post-open stat must be a directory. Every effect syscall
   from here on — snapshot, temp open, write, rename — runs **at-relative to
   that descriptor** (`openat`, `fclonefileat`, `renameat`, `unlinkat`), never
   against the path string. Resolving the path string per syscall would
   re-resolve it independently every time, and each re-resolution is a window
   in which an agent with write access to an intermediate directory can swap a
   path component (move the real directory aside and plant a symlink at the
   same path) and steer the write into a different directory — possibly
   outside the configured prefixes. The pin makes the next bound hold against
   the directory that is actually written. If the parent cannot be opened or
   verified, the effect fails: `Authorized` is audited first, then
   `ExecutionFailed` (the decision was made; the effect cannot run).

   The supervisor also enforces its own **outer bound**: the pinned canonical
   target (not a fresh path lookup) must fall within a configured allowed
   prefix. The token's `allowed_prefix` facts are the capability grant; this is
   the outer bound the supervisor itself enforces. If it is violated the
   request is `Denied` (`ConstraintViolated`), audited, and no `Authorized`
   record is written.
4. Append audit `Authorized`, including `snapshot_path` and the SHA-256 of the
   content to be written. Durable before proceeding (invariant 2). The snapshot
   path is deterministic (below), so it can be recorded before the snapshot
   exists. **The snapshot is a state mutation and invariant 2 covers it: the
   audit must precede it, and a crash between audit and snapshot is visible as
   an `Authorized` with no terminal record.**
5. Take the snapshot (`Overwrite` only): open the target through the pin
   (`openat` `O_RDONLY | O_NOFOLLOW`; it must be a regular file), then
   `fclonefileat(target_fd, snapshots_dir_fd, snapshot_name)`. The snapshot is
   a clone of the opened file, so it captures the content of the file that
   was authorized, whatever the path string comes to refer to afterwards. The
   snapshot file is created `0600` explicitly (not `umask`-dependent): it is a
   pre-image of content the agent wrote.
   `snapshot_path` is
   `<state_dir>/snapshots/<session_id>.<request_id>.<sanitized_basename>`.
   The session id is supervisor-generated, so uniqueness does not depend on the
   client at all (`01-protocol.md` §3 does not guarantee cross-connection
   uniqueness of request ids). The basename is sanitized to
   `[A-Za-z0-9._-]`, truncated to 64 bytes, and is a human-readable suffix
   only. The clone requires the destination not to exist; the naming scheme
   makes collision impossible.
   Failure → `Error/ExecutionFailed`, audit `ExecutionFailed`, **no write is
   attempted**. If the target is on a different volume than the state
   directory, the clone fails with `EXDEV`; the supervisor maps this to a
   stable `Error/ExecutionFailed` message — never a raw errno — so the client
   learns what to fix (a prefix created or mounted on another volume after
   startup is the realistic case; startup verification only covers what
   exists then).
6. Write, with the mechanism split by mode; every syscall is at-relative to
   the pinned directory fd:
   - `Create`: `openat(dirfd, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0644)`,
     write, `fsync` the file, `fsync` the directory. The kernel provides the
     atomic "fail if exists". A crash mid-`Create` leaves a partial new file —
     that is acceptable because there is no prior content: `Authorized` with no
     `Executed` fully describes it, and deleting the file is a complete
     recovery.
   - `Overwrite`: create a temp file in the pinned directory, write, `fsync`
     the file, `renameat` over the target, `fsync` the directory. The
     atomic-rename pattern means a crash mid-write leaves either the old file
     or the new one, never a truncated one.
7. Append audit `Executed` with bytes written and the restore handle.

If step 6 fails after step 5, the log shows `Authorized` followed by
`ExecutionFailed` and the snapshot remains. That is the correct observable
state.

**Documented race.** `Overwrite` can silently create if the target is deleted
between the open (step 5) and the rename (step 6): the snapshot was taken
through the still-open file, so the pre-image is intact, and the rename
re-creates a new file at the target path holding authorized content. The
residual window is narrow; the outcome (a file inside the allowed prefix
holding authorized content, with a recoverable pre-image) remains within the
grant. This is documented, not hidden.

### On APFS and `clonefile`

`clonefile(2)` is copy-on-write and effectively free regardless of file size,
which is what makes snapshot-before-write affordable enough to do unconditionally.

It requires APFS. At startup, verify the state directory's filesystem is APFS
(`statfs` → `f_fstypename`). If it is not, **refuse to start** rather than
falling back to a byte copy. A byte copy has different cost and different
failure modes, and a supervisor that silently switches between them makes the
`Trivial` classification a lie under conditions nobody tested. Failing at
startup makes the requirement explicit.

The snapshot and the target must be on the same volume — `clonefile` does not
cross volumes. Verify at startup that the state directory and the configured
allowed prefixes share a device id, and refuse otherwise. This is a real
constraint that will be hit by anyone whose work directory is on an external
disk, and discovering it at first write is much worse than at startup.

The state directory and its `snapshots/` subdirectory are created — or
verified — `0700` at startup: they hold pre-images of agent-written content
and, next door, the audit chain, and nothing outside the supervisor's user
should be able to read or tamper with them.

### Response

```json
{
  "status": "Ok",
  "result": {
    "path": "/Users/austin/work/notes.md",
    "bytes_written": 14,
    "content_sha256": "a3f1...",
    "restore": {
      "kind": "Snapshot",
      "handle": "01J8ZS....01J8ZQ....notes.md",
      "reversibility": "Trivial"
    }
  }
}
```

`path` is the canonicalized path, which may differ from what the client sent. It
must be returned so the client learns what actually happened rather than
assuming its input was used verbatim.

`restore.handle` is opaque to the client. There is no restore operation in v0 —
the handle is recorded so a future `Restore` operation, or a human with the
audit log, can find the snapshot. Do not implement `Restore` now; do make sure
the handle is sufficient to implement it later.

### Snapshot retention

Snapshots accumulate. v0 does not garbage-collect them.

Retention is a policy question entangled with reversibility windows and with
whatever `Restore` ends up looking like, and a GC that deletes a snapshot still
referenced by an unexpired reversibility guarantee would quietly break the
property the whole classification exists to provide. Let them accumulate; they
are CoW clones and cost little until the original changes.

Document the growth in the README so it is a known cost rather than a surprise.

### Acceptance criteria (M6)

- [ ] Authorized `Overwrite` writes content, returns a restore handle, and the
      snapshot at the handle contains the **original** bytes.
- [ ] Authorized `Create` on a nonexistent path succeeds; on an existing path
      returns `Error/ExecutionFailed` (`O_EXCL`) and does not modify the file.
- [ ] `Overwrite` on a nonexistent path returns `Error/ExecutionFailed`
      (`clonefile` fails at step 4); audit shows `Authorized` followed by
      `ExecutionFailed`; the target is not created.
- [ ] Denied write leaves the target byte-identical and creates no snapshot.
      Assert on file mtime as well as content.
- [ ] Path outside the token's prefix → `Denied/ConstraintViolated`; no snapshot,
      no write.
- [ ] `path` targeting `audit_path` → `Denied/ControlPlaneProtected`.
- [ ] Final component is a symlink whose target is inside the allowed prefix →
      `Denied/ConstraintViolated`. This proves the refusal is categorical, not
      a prefix check in disguise. Write the test with the symlink created
      *before* the request; the race variant is covered by `04-guard.md` §6
      steps 3–6 and is not directly testable, so note it.
- [ ] Final component is a symlink whose target is outside the prefix →
      `Denied/ConstraintViolated`.
- [ ] Symlinked parent directory resolving outside the allowed prefix → denied.
- [ ] Content over 256 KiB → `Error/MalformedRequest`; no `Authorized` record.
- [ ] Invalid base64 → `Error/MalformedRequest`; no `Authorized` record.
- [ ] Snapshot failure path: make the snapshot directory read-only, issue an
      `Overwrite`, and assert the target is unmodified and the audit shows
      `Authorized` followed by `ExecutionFailed` with no write attempted.
- [ ] Audit ordering: `Authorized` (with snapshot path and content hash)
      strictly precedes the snapshot and the write. Verify by asserting the
      audit file's size or last `seq` from a hook between steps 3 and 5.
- [ ] `SIGKILL` between audit and write leaves `Authorized` with no terminal
      record; verifier reports a crash-window warning at the tail.
- [ ] Startup refuses on a non-APFS state directory.
- [ ] Startup refuses when an allowed prefix is on a different device than the
      state directory.
- [ ] `content_sha256` in the response matches an independent hash of the file
      on disk after the write.
