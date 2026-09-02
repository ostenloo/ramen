# CI workflows

Orientation for anyone — human or agent — about to change anything in this
directory. Read the "Before you edit" rules first; two of them will silently
break the pipeline if ignored, and the breakage looks like success.

## The pipeline

Four workflows. `ci` is the only one that builds and tests; the other three
react to it.

```
push/PR ──> ci ──failure on main──> ci-doctor ──> issue (label: ci-failure)
                │                                        │
                │                                   (hourly queue)
                │                                        v
                │                                    ci-fixer ──> PR
                │                                                  │
                └──success on a PR run──> auto-merge ──> squash, or needs-human
                │
                └──success on main──> ci-doctor resolve ──> closes ci-failure issues
```

| File | What it is | Runs on |
|---|---|---|
| `ci.yaml` | build + test + lint. 5 jobs, macOS except `spec-drift` | any push, any PR |
| `ci-doctor.yml` | plain YAML, no model. Diagnoses failures, owns issue lifecycle | after `ci` completes on `main` |
| `ci-fixer.md` + `.lock.yml` | gh-aw agentic workflow. Writes fixes, opens PRs | hourly cron + `workflow_dispatch` |
| `auto-merge.yml` | plain YAML, no model. The merge gate | after `ci` completes on a PR run |
| `agentics-maintenance.yml` | gh-aw housekeeping (safe-output expiry) | daily cron |

**Only `ci-fixer` uses a model.** Diagnosis and merging are mechanical and are
deliberately kept that way — see the design note in each file's header.

## Before you edit

### 1. `ci-fixer` is generated. Never edit one half alone.

`ci-fixer.lock.yml` is compiled from `ci-fixer.md`, and stores hashes of that
file's frontmatter and body. Editing the `.md` without recompiling fails at
activation with `E009 CONFIG_HASH_MISMATCH`. Editing the lock file's *step
content* is fine (that is not hashed).

```bash
gh aw compile ci-fixer                    # regenerate the lock file
python3 .github/scripts/patch-locks.py    # MANDATORY afterwards — see below
```

### 2. `gh aw compile` reverts five hand-applied fixes. Re-apply them.

The AWF sandbox needs patches that have no frontmatter knob, so they live in
the lock file and are wiped by every recompile. `patch-locks.py` re-applies
them and asserts an expected occurrence count on each, so a change in the
generator's output fails loudly instead of half-patching. It is idempotent —
run it whenever unsure.

The five: firewall pinned to `v0.28.12` (earlier versions dial https-on-443 and
cannot reach a plaintext local endpoint), MCP gateway port `18080` (8080 is
taken on the runner host), zero AI-credit pricing (the proxy meter 400s on
models absent from its pricing table), `http://172.17.0.1` as the upstream
target plus both forms in `allowDomains`, and `maxCacheMisses: 500` for the
detection job.

That last one is the nastiest and worth understanding: the proxy counts a cache
miss on every response with `cache_read_tokens == 0` and returns HTTP 403 once
the streak hits the cap. vLLM never reports cached tokens, so **every** turn is
a miss — the agent dies mid-run at request 6, and the harness misreports it as
`authentication_failed`. Do not go looking at provider keys.

### 3. Only green CI closes a `ci-failure` issue.

Open/closed tracks **reality** (is CI failing?). Labels track **the queue** (has
anyone claimed it?). Consequences:

- `ci-fixer` must **not** close issues. It has no `close-issue` safe output;
  do not add one. Opening a PR records that work happened, not that the failure
  is gone.
- Agent PRs say `Refs #N`, **never** `Fixes #N`. The closing keyword makes
  GitHub close the issue on merge, asserting a fix worked before anything
  verified it. (Repo setting "auto-close issues with merged linked PRs" is on,
  which is correct for ordinary human PRs.)
- `ci-doctor`'s `resolve` job closes open `ci-failure` issues when `ci` passes
  on `main`. A green run means every job passed, so nothing recorded still
  reproduces. This also catches fixes that arrived outside the pipeline — a
  direct push, a revert — which a merge-based rule never would.
- Dedup matches fingerprints across **closed** issues too and **reopens**.
  Without that, auto-close defeats fingerprinting and a flake files a fresh
  issue after every green run. A ticket that visibly reopens reads as "flaky";
  a pile of duplicates does not.

### 4. `ci.yaml` sets `CARGO_TERM_COLOR: never` for a reason.

cargo colourises even on a non-TTY, and the escapes land *between* `error` and
its colon — so the string `error:` does not occur in the raw log at all.
`ci-doctor` strips colour itself as a second layer, so removing this degrades
rather than breaks, and a degraded report says so in the issue body. Still,
verify the doctor names a file and line before merging any change to it.

### 5. Labels must exist before a workflow references them.

A missing label is a hard failure, not a warning — it fails the whole
safe-outputs step. Required: `ci-failure`, `ci-fix-in-progress`, `needs-human`.

## The merge gate

`auto-merge.yml` merges a PR only if **all** hold; anything else gets
`needs-human` and a comment naming the failed condition. A rejection is an
expected outcome, not an error — the job succeeds either way.

1. `ci` green on the PR's head SHA
2. Title starts `[ci-fixer]` **and** body carries the `gh-aw-workflow-id` marker
3. additions + deletions ≤ 50
4. No protected paths: `.github/`, `spec/`, `deploy/`,
   `crates/ramen-proto/src/`, `crates/ramen-guard/src/`
5. No test files or build files: `*/tests/*`, `*test*.rs`, `Cargo.toml`,
   `Cargo.lock`, `*.md`
6. No `spec: n/a` in any commit message

Condition 5 is the important one: the classic agent failure is fixing the test
to match the bug — small, compiles, turns CI green, and passes every other
check. Condition 6 stops an agent granting itself a spec-drift exemption.

Because `.github/` is protected, **an agent cannot modify these workflows**.
Changes here are human-reviewed by construction.

Two operational notes:
- The gate promotes the PR with `gh pr ready` before merging. gh-aw creates
  drafts and GitHub refuses to merge a draft; without this, a PR passes all six
  conditions and then fails at the merge call.
- **Rebase agent PRs, never merge into them.** Merging `main` in drags
  unrelated commits into the PR's commit list, and those may contain
  `spec: n/a` — tripping condition 6 on an otherwise valid PR.

## Runner and model

`ci-fixer`'s agent and threat-detection jobs run on the self-hosted
`ramen-fedora` runner (`[self-hosted, linux, x64]`); framework jobs stay on
hosted runners. The model is local vLLM (`qwen3.8-27b-awq`) reached at
`http://172.17.0.1` through a Caddy route to port 8000. No cloud model is used
anywhere in this pipeline, by design — trust lives in the deterministic gate,
not in a second model's opinion.

## Testing changes

- **`ci-doctor`** — needs a real failure on `main`. Its `resolve` job needs a
  green run on `main`. Both are ~25s once triggered.
- **`ci-fixer`** — `gh workflow run ci-fixer.lock.yml`. No-ops unless an open
  issue has `ci-failure` and lacks `ci-fix-in-progress`. Takes 3–8 min on the
  local model.
- **`auto-merge`** — needs an open PR with a green `pull_request` run. It reads
  only the `pull_request` run, never the `push` run on the same branch.

**Verify against the runner, not just locally.** Several fixes here passed
offline and failed live because local tooling encodes things differently
(`gh` renders ANSI differently, BSD vs GNU `sed` differ on `\t` and `\x1b`
escapes, `awk -v` mangles backslashes in patterns). If offline checks keep
passing while live runs keep failing, stop guessing and dump the actual bytes
the runner sees.

## Known gaps

- Nothing deletes branches from attempts that never merged — PR creation
  failed, PR closed unmerged, or gh-aw's 7-day expiry closed it. Automatic
  head-branch deletion only covers merged PRs.
- The reopen path in `ci-doctor` has not fired in production yet.
- The `needs-human` rejection path in `auto-merge` has not fired in production
  yet.
