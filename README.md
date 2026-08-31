# Ramen

Ramen is a supervisor-based control plane that mediates operations performed by
software agents. Agents do not act directly: they submit operation requests to
a privileged supervisor process over a Unix domain socket. The supervisor
authenticates the caller (code signature), authorizes the specific operation
against a Biscuit capability token, records the decision in an
append-only, hash-chained audit log, and only then performs the operation on
the agent's behalf.

This repository contains the **v0 core**: the vertical slice from wire
protocol through authorization, audit, and two concrete operations
(`Whoami`, `FileWrite`), plus an out-of-band token minter. The authoritative
specification lives in [`spec/`](spec/) and changes with the code it describes.

## Invariants

These hold in every code path (full text: `spec/00-overview.md`):

1. **No unmediated action** — an effect runs only after a successful
   authorization decision for that specific operation.
2. **Audit precedes effect** — mutating operations are `fsync`ed to the audit
   log *before* the effect. A crash in between leaves a recorded intent with
   no effect, never the reverse.
3. **Denials are audited** with the same rigor as authorizations.
4. **No silent degradation** — if the supervisor cannot enforce (audit
   unwritable, root key unavailable, peer identity unverifiable), it refuses
   service.
5. **The control plane is not an operable surface** — no operation can touch
   the supervisor's own configuration, audit log, keys, or socket.
6. **Authorization and audit integrity are separate mechanisms** — Biscuit
   answers "is this caller permitted"; the hash chain answers "has the record
   been altered".

## Layout

```
crates/
  ramen-proto/       envelopes, codec, reversibility (no I/O)
  ramen-audit/       append-only log, hash chain, `ramen-audit-verify` binary
  ramen-guard/       Biscuit verification, capability model, deny path
  ramen-supervisor/  the daemon binary
cli/
  ramen-mint/        out-of-band token minter (holds the root private key)
spec/                the specification (authoritative, moves with the code)
```

Milestones M1–M6 of `spec/00-overview.md` are implemented. M7
(`ramen-sdk` / `ramenctl`) follows.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

Target platform for v0: macOS 13+ (Apple Silicon or x86_64). Platform-specific
code (code signing, `statfs`, `clonefile`) is confined to
`ramen-supervisor::platform::darwin`.

## Running the supervisor

```sh
ramen-supervisor --config <path>
```

The config is TOML; there is no default search path and no environment
overrides. A group- or world-writable config file is a startup refusal.
Required fields: `socket_path`, `audit_path`, `root_key_path`, `state_dir`,
`[peer] requirement` (a raw `SecRequirement` string, e.g.
`identifier "com.example.agent"`). Optional: `allowed_prefixes` — the
supervisor-level bound on `FileWrite` targets; empty means no `FileWrite` can
ever succeed (fail closed).

Startup checks, any failure aborts:

- config file mode/ownership and schema
- audit log chain integrity (a corrupt chain is a refusal)
- root key is a **public** key (a private key is refused)
- the state directory is on **APFS** and every existing `allowed_prefixes`
  entry shares its device id (`clonefile(2)` is APFS-only and does not cross
  volumes — the supervisor refuses to start rather than fall back to byte
  copies)
- the socket path is free and the socket is created `0600`

### Tokens

`ramen-mint` holds the root private key (`~/.ramen/root.key`, `0400`); the
supervisor only ever sees the public key.

```sh
ramen-mint keygen
ramen-mint issue --root-key ~/.ramen/root.key --identity agent:planner ...
```

### Verifying the audit log

```sh
ramen-audit-verify <audit.log>
```

Exits 0 on a valid chain, 1 on a tamper/truncation/crash-window finding, 2 on
a usage error. The verifier is standalone: it trusts nothing in the
supervisor.

## Snapshot retention (known cost)

Every authorized `FileWrite` in `Overwrite` mode takes a `clonefile(2)`
(APFS copy-on-write) snapshot **before** the write, stored under
`<state_dir>/snapshots/<request_id>.<basename>`. The snapshot is what makes
the write `Trivial`-reversible: the original bytes can be restored locally
with no external coordination.

**v0 does not garbage-collect snapshots.** They accumulate for the lifetime
of the state directory. They are CoW clones, so each costs only the metadata
of the original file until the original file's blocks change — but on
workloads that overwrite large files frequently, the count (and, once the
originals are modified, the bytes) will grow without bound. Plan the state
directory's volume size accordingly, and treat manual cleanup of
`<state_dir>/snapshots/` as an operator action: deleting a snapshot that an
unexpired reversibility guarantee still references breaks that guarantee.

## v0 is deliberately faked

- **Root key custody** uses a file-backed P-256 key behind the `RootKey`
  trait; the Secure Enclave implementation is a drop-in later. P-256 is used
  from day one because the Secure Enclave only does P-256.
- **Local mode only**: no attestation, no remote issuance, no managed mode.

Out of scope for v0 (by design, no extension points added): microVM
sandboxing, Endpoint Security interception, PTY hosting, GUI, filesystem
snapshots beyond `clonefile`, restore operations.
