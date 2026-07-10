# Changelog

All notable changes to Warden are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/).

## [1.5.3] — 2026-07-10

The performance budget: Warden's overhead is now a published,
regression-tracked number. Measured median overhead per mediated tool call:
**≈ 2 ms** end to end over real pipes, with sub-0.1 ms policy evaluation and
the deny path effectively free (0.004 ms) — deny-by-default costs nothing.

### Added
- `benchmarks/bench.py`: measures every pipeline stage (normalize, policy
  allow/deny, full mediation, audit write) at median/P95/P99 over 2,000
  iterations, plus live transport round-trip overhead against the fake MCP
  server over real pipes, plus peak RSS. `--json` output for tracking.
- `docs/PERFORMANCE.md`: published reference numbers with methodology and
  interpretation.
- `tests/test_performance.py` (5 tests): generous regression ceilings so an
  accidental O(n^2) in the hot path fails CI instead of shipping, including
  an invariant that the deny path never becomes anomalously slower than the
  allow path.

## [1.5.2] — 2026-07-10

Fuzz and property testing of the Normalize boundary — the first trust
boundary in the pipeline, so it deserves abuse. The suite immediately earned
its keep: it found two ways a hostile peer could crash the relay.

### Added
- Hypothesis-driven fuzz/property suite (`tests/test_fuzz_normalize.py`,
  19 tests): random Unicode including lone surrogates, controls, bidi and
  zero-width characters; malformed structures; deep nesting; null bytes;
  huge strings.
- Invariants proven as properties: `harden()` is total, deterministic,
  idempotent, and its output is free of invisibles, hidden controls, null
  bytes, and mapped homoglyphs; `Request.normalize()` is total, never
  mutates its input, and its inspection view is itself fully hardened;
  `parse_jsonrpc_line()` never raises and only returns a dict or None.
- `hypothesis` added to requirements.

### Fixed
- **Relay crash vectors found by the fuzz suite.** The transport pumps
  guarded only `json.JSONDecodeError`, so a deeply nested line
  (`'[' * 100000`) escaped as `RecursionError`, and valid non-object JSON
  (`[1,2,3]`) crashed the server pump with `AttributeError` on `.get()`.
  Either one killed the mediation relay — an availability attack against
  the security layer itself. Both pumps now parse through a fail-closed
  `parse_jsonrpc_line()` that returns a dict or None, never an exception;
  hostile lines are dropped and the relay keeps running.


## [1.5.1] — 2026-07-08

The release-defining feature of the Registry Hardening phase:
**tool-definition pinning**. The trust boundary now covers what a tool *is*,
not just what it does — defense against MCP rug-pull / tool-poisoning, where
a server advertises a benign tool at approval time and swaps its definition
later.

### Added
- Canonical schema serialization: order-independent, whitespace-independent
  JSON canonicalization so semantically identical schemas hash identically.
- SHA-256 schema hashing of every advertised tool definition.
- Persistent tool registry: name, version, canonical schema, hash, approval
  state, approved-at, approved-by.
- Registry versioning: full hash history per tool; every schema change is a
  new version linked to its predecessor, so tool evolution carries its own
  audit trail.
- Drift detection: advertised schemas are re-hashed on every connect; a
  changed hash without re-approval is denied (rule PIN-001).
- Reapproval workflow: a drifted tool is quarantined until a human approves
  the new schema; approval is recorded with the new hash and version.
- Audit events for register / approve / drift / reapprove, parent-linked on
  the hash chain.
- Unit and integration tests for the full pinning lifecycle.

## [1.1.0] — 2026-07

Full security code review of the v1 runtime, with every high- and
medium-severity finding remediated and regression-tested. 133 tests grew to
148; all passing.

### Fixed
- **High:** late server replies could bypass inspection after a watchdog
  timeout; late replies are now dropped and audited.
- **High:** the human approval gate blocked the event loop; approval prompts
  now run without stalling concurrent mediation.
- **Medium:** check-versus-execute gap in path handling — the canonical path
  was validated but the original path was forwarded; the canonical path is
  now the one executed.
- **Medium:** the pinning layer failed open for never-advertised tools when a
  registry was configured; unknown tools now fail closed.
- Shipped `policy.yaml` gained explicit egress, mode, and timeout
  configuration; stale comment removed from inbound inspection; redactor
  extended to `sk-proj-`-style key formats; entropy sweep no longer clips
  base64 padding; multi-argument path attribution corrected; audit log now
  uses WAL and synchronous pragmas.

## [1.0.0] — 2026-07

v1 exit milestone: the complete inspection-and-enforcement runtime,
demonstrable against live agent traffic.

### Added
- Deny-by-default tiered policy engine with schema-validated YAML config and
  a built-in deny-all default when no policy is present.
- Request normalization with Unicode hardening (NFKC, zero-width/bidi
  stripping, homoglyph folding) ahead of every inspector.
- Path canonicalization confining all filesystem access to a workspace root.
- Safe subprocess execution guard (`shell=False` argument vectors only).
- Credential and PII detection on arguments; response-path redaction wired
  end to end.
- Indirect prompt-injection inspection of tool responses, live in the
  transport.
- Explainable Decision object: rule id, risk score, reason, suggested fix,
  audit id.
- Risk scoring with documented weights; Mission Mode (declared intent and
  allowed capabilities; everything outside denied).
- Real MCP stdio JSON-RPC transport: Warden physically between client and
  server, with execution watchdog, graceful drain, and generic errors to the
  agent while rule detail stays in the audit log.
- Minimal egress allowlist (rule EGR-001) on URL-bearing arguments.
- Minimal human approval gate; every failure mode resolves to DENY.
- Fail-closed guarantees proven by fault-injection tests on every pipeline
  stage; monitor mode for log-only rollout.
- Hash-chained SQLite audit log with immutable event IDs and `warden verify`
  independent chain verification.
- CLI: `init`, `inspect`, `run`, `verify`.
- Synthetic attack test suite; per-rule regression tests; CI on every push.
- `docs/THREAT_MODEL.md` defense-to-threat mapping.
