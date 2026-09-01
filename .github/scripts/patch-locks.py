#!/usr/bin/env python3
"""Re-apply the AWF post-compile patches to the gh-aw lock files.

`gh aw compile` regenerates <workflow>.lock.yml from <workflow>.md and in
doing so reverts every hand-applied AWF fix. None of these have a compiler
knob (the one that did -- the cache-miss cap -- is now the
`max-turn-cache-misses` frontmatter key, and only reaches the agent job).
Run this after every compile. It is idempotent and asserts on every
substitution, so a silent partial patch is not possible.

    python3 .github/scripts/patch-locks.py [workflow ...]   # default: ci-fixer ci-doctor

Background for each patch is in the commit history (see cc4a50d,
d7b4025, d608e40, 414689c, a9d2f35).
"""

import sys
import pathlib

# v0.28.10 -> v0.28.12: 0.28.10's api-proxy normalizeApiTarget() keeps the
# hostname only and always dials https-on-443, so an explicit host:port
# upstream gets silently rewritten to :443. 0.28.12 preserves an explicit
# http:// scheme (cleartext port 80). Digests from the release containers.txt.
FIREWALL_OLD = "0.28.10"
FIREWALL_NEW = "0.28.12"
DIGESTS = {
    "agent":     ("c01e6d16d11ea4f2a46cc023a9f402224a3b3861b026818eec0dc586d7e6918e",
                  "390051be4ed1847f774fd8980b61d3a3523574c0175d00c3fc7cdf2002a88202"),
    "api-proxy": ("c3a18aebb8251339117ea998296315de17bada366f8d03919b3348ea71112e64",
                  "d7d533d87c80d87ff91ac0e21e9299055c3beedff1536262b97ed700fb065a32"),
    "squid":     ("c06076f7aca95df713e0748c44d80c0a3c2538fad67bfdd04296d45158e083e6",
                  "52c34aca98d2a6833c329f1505912a6949c4fda16618c010c979bd59ea99254f"),
    "cli-proxy": ("a61070cb7f21840c5f2ec74d55b49adf0652d0348ce059015aaaca33a8cb6b45",
                  "5250629d48eaedfedf2e948785228e8da29eec2a83cbab58ea0751c14a7b021d"),
}

PATCH_NOTE = """          # POST-COMPILE PATCHES -- re-apply after every `gh aw compile` with
          # `python3 .github/scripts/patch-locks.py` after every `gh aw compile`.
          # 1. MCP gateway host port: the generator hardcodes 8080, which is
          #    occupied by mirgenta-server on this self-hosted runner's host.
          # 2. AI-credits pricing: the api-proxy meter 400s on models absent
          #    from its pricing table; zero pricing = free local vLLM.
          # 3. Upstream target: explicit http:// => cleartext port 80 -> Caddy
          #    (handle /v1/* -> 127.0.0.1:8000) -> vLLM. Requires firewall
          #    >=0.28.12. allowDomains carries both the bare and http- forms
          #    because the binary/squid ACL compares the string as written.
          # 4. Cache-miss cap: vLLM never reports cached_tokens, so every turn
          #    counts as a miss and the default of 5 kills the agent mid-run
          #    with a 403 the harness mislabels as an auth failure. The agent
          #    job gets its value from `max-turn-cache-misses` in frontmatter;
          #    that key does not reach the detection job, so it is patched.
"""


class Patcher:
    def __init__(self, path):
        self.path = path
        self.text = path.read_text()
        self.log = {}

    def sub(self, name, old, new, expect=None, at_least=None):
        n = self.text.count(old)
        if old == new:
            raise SystemExit(f"{self.path.name}: {name}: no-op substitution")
        if expect is not None and n != expect:
            raise SystemExit(
                f"{self.path.name}: {name}: found {n} occurrence(s), expected {expect}. "
                "The generator's output shape changed -- re-derive this patch by hand."
            )
        if at_least is not None and n < at_least:
            raise SystemExit(
                f"{self.path.name}: {name}: found {n}, expected >= {at_least}."
            )
        self.log[name] = n
        self.text = self.text.replace(old, new)

    def save(self):
        self.path.write_text(self.text)


def patch(path):
    p = Patcher(path)
    already = FIREWALL_OLD not in p.text.replace(
        f"the v{FIREWALL_OLD} api-proxy", ""
    )

    # 1. firewall version bump (version strings, schema URL, install script,
    #    imageTag pins) + the four image digests
    if not already:
        p.sub("firewall-version", FIREWALL_OLD, FIREWALL_NEW, at_least=1)
    for img, (old, new) in DIGESTS.items():
        if old in p.text:
            p.sub(f"digest:{img}", old, new, at_least=1)

    # 2. MCP gateway host port
    if 'export MCP_GATEWAY_PORT="8080"' in p.text:
        p.sub("gateway-port", 'export MCP_GATEWAY_PORT="8080"',
              'export MCP_GATEWAY_PORT="18080"', expect=1)

    # 3. zero AI-credit pricing, both AWF configs
    if r'\"defaultAiCreditsPricing\"' not in p.text:
        p.sub("pricing",
              r'\"maxAiCredits\":${GH_AW_MAX_AI_CREDITS},',
              r'\"maxAiCredits\":${GH_AW_MAX_AI_CREDITS},'
              r'\"defaultAiCreditsPricing\":{\"input\":0,\"output\":0},',
              expect=2)

    # 4. allowDomains: the ACL compares the target string as written, so the
    #    http- form must be listed too. Two emitted shapes: the detection
    #    job's list terminates after 172.17.0.1, the agent job's continues.
    #    Guarded on its own patched marker -- checking for the http- form
    #    anywhere in the file would be satisfied by patch 5's target host.
    #    Must run BEFORE patch 5 for the same reason.
    ALLOW_PATCHED = r'\"allowDomains\":[\"172.17.0.1\",\"http://172.17.0.1\"'
    if ALLOW_PATCHED not in p.text:
        # `long` first: its pattern ends in a comma so it cannot match the
        # terminating `short` form, whereas `short`'s output would be matched
        # by `long` and get a second insertion.
        if r'\"allowDomains\":[\"172.17.0.1\",' in p.text:
            p.sub("allowdomains-long",
                  r'\"allowDomains\":[\"172.17.0.1\",',
                  r'\"allowDomains\":[\"172.17.0.1\",\"http://172.17.0.1\",',
                  at_least=1)
        if r'\"allowDomains\":[\"172.17.0.1\"]' in p.text:
            p.sub("allowdomains-short",
                  r'\"allowDomains\":[\"172.17.0.1\"]',
                  r'\"allowDomains\":[\"172.17.0.1\",\"http://172.17.0.1\"]',
                  at_least=1)

    # 5. upstream target scheme, both AWF configs
    if r'\"host\":\"172.17.0.1:8000\"' in p.text:
        p.sub("target-scheme",
              r'\"targets\":{\"copilot\":{\"host\":\"172.17.0.1:8000\"}}',
              r'\"targets\":{\"copilot\":{\"host\":\"http://172.17.0.1\"}}',
              expect=2)

    # 6. detection job's cache-miss cap (frontmatter key reaches only the agent)
    if r'\"maxCacheMisses\":5,' in p.text:
        p.sub("detection-cache-misses",
              r'\"maxCacheMisses\":5,', r'\"maxCacheMisses\":500,', at_least=1)

    # 7. patch notes, so the next reader of the lock knows these exist
    if "POST-COMPILE PATCHES" not in p.text:
        p.sub("patch-note", '          export MCP_GATEWAY_PORT="18080"',
              PATCH_NOTE + '          export MCP_GATEWAY_PORT="18080"', expect=1)

    p.save()
    return p.log


def main():
    names = sys.argv[1:] or ["ci-fixer", "ci-doctor"]
    root = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
    for name in names:
        path = root / f"{name}.lock.yml"
        if not path.exists():
            raise SystemExit(f"no such lock file: {path}")
        log = patch(path)
        applied = ", ".join(f"{k}={v}" for k, v in log.items()) or "nothing (already patched)"
        print(f"{name}: {applied}")


if __name__ == "__main__":
    main()
