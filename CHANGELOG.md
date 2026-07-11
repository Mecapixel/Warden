# Changelog

All notable changes to Warden are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/).

## [5.0.0] — 2026-07-11

**v5 — Runtime Containment.** Isolate execution environments and limit
blast radius. The downstream MCP server no longer has to run naked on the
host: Warden provisions the sandbox it runs in — Warden, not the workload's
own configuration, because a box the workload can describe is decoration.
Absent a `containment:` block, nothing changes. 61 new tests; the entire
subsystem is exercised with injected backend detection and injected process
tables — no Docker daemon, overlay mount, or /proc required, which is
itself the property being tested.

### Added
- `proxy/containment/backends.py`: the isolation ladder — Docker (namespace
  /cgroup isolation, shared kernel) → gVisor (userspace kernel, syscalls
  never reach the host directly) → Wasmtime (no ambient kernel, filesystem,
  or network to escape into; workload must be a wasm module, and
  pretending otherwise is refused rather than silently downgraded).
  Detection probes through an injectable runner; selection is
  required-or-STRONGER, never weaker — a host that cannot provide the
  required rung is SBX-001 at provision time, not a quiet fallback.
- `proxy/containment/sandbox.py`: provisioning with a non-negotiable floor.
  Every spec has network `none` (outbound access goes through the v3 egress
  battery at the proxy — the sandbox is not a second network path),
  read-only rootfs, cap-drop ALL, no-new-privileges, and a size-capped
  noexec/nosuid tmpfs; any attempt to construct a spec below the floor is
  SBX-002 by construction — there is no code path that produces an open
  spec. Rendering produces argv as data; nothing in the package executes.
- `proxy/containment/ephemeral.py`: the writable surface dies with the run.
  Overlay mode renders a Linux OverlayFS spec (read-only lower layer,
  provably untouched because overlay never writes to it); staging mode
  works everywhere else and the audit record names which mode was in play
  — recorded, never blurred. Destruction is VERIFIED: destroy() re-checks
  the tree, and survivors are an EPH-001 violation with every survivor
  named, treated as a persistence attempt until proven otherwise.
- `proxy/containment/quotas.py`: CPU / memory / disk / pids / wall clock.
  Validated positive at load — a zero, negative, or MISSPELLED quota is a
  startup policy error, never a silent "unlimited". Docker rendering pins
  swap equal to memory so the cap has no overflow valve; the wall-clock
  Deadline is held by Warden with an injectable clock, because a wedged
  workload does not get a vote on whether it has timed out (QUO-001).
- `proxy/containment/procmon.py`: what the workload DOES with its process
  table — fork breaches counted through the whole descendant tree so
  forking through an intermediary doesn't launder the count (PROC-001),
  zombie accumulation with zero tolerance by default (PROC-002), overstay
  judged on Warden's clock (PROC-003), and descendants running executables
  outside the declared allowlist (PROC-004). Snapshots arrive through an
  injectable provider (/proc walker supplied for Linux hosts); a provider
  failure reports the monitor as blind (PROC-000) — blind is not clean.
- Transport integration: `MCPProxy` accepts a ProvisionedSandbox and spawns
  the sandbox argv with the real server command inside it; the containment
  posture (isolation level, image, floor flags, quotas) is recorded on the
  audit chain before the first byte of protocol flows, so every decision in
  the run is attributable to a known isolation level. Policy validation
  rejects malformed `containment:` config at load, including the
  wasmtime-without-a-module contradiction.
- `tests/test_v5_containment.py`: 61 tests — ladder selection in every
  direction, floor unbreachability, argv posture assertions, verified
  destruction with named survivors, quota load-validation, deadline
  behavior, all five process signatures, and transport integration.

## [4.0.0] — 2026-07-11

**v4 — Identity & Trust.** Who is asking, what exactly are they entitled to
do, who signed off, and can the agent's memory be trusted. The minimal
approval gate shipped in v1; this release generalizes it and adds the
identity layer around it. Absent an `identity:` block in policy, every new
control is inert and v1–v3 behavior is unchanged. 64 new tests.

### Added
- `proxy/identity/rbac.py`: agent RBAC — the invoking user's role
  INTERSECTED with the agent deployment's scope, the same narrow-never-
  widen law as v3 egress scopes. Unknown users have no role and no role
  means no tools (RBAC-001) unless the operator deliberately opts into
  anonymous access with `default_role`; a tool the user's role permits but
  the deployment scope excludes is RBAC-002. An empty declared scope means
  the agent may run nothing — the distinction from "no scope declared" is
  preserved.
- `proxy/identity/capabilities.py`: capability tokens — per-request,
  HMAC-SHA256-signed, scoped grants (`filesystem.read` on
  `/workspace/data/*`, `network.egress` on a host) minted by a per-session
  issuer whose key exists only in memory. Unforgeable (one flipped byte
  fails constant-time verification), bounded in time (injectable clock),
  single-use by default (replay is CAP-002), and revocable at the root:
  session close discards the key and every outstanding token dies with
  it. The engine checks grants against the CANONICAL target — the path
  after canonicalization, the host after extraction — so a grant cannot
  be stretched with `..` games or URL dressing.
- `proxy/runtime/approval.py` generalized: per-capability approval
  policies (`always`, `risk>=N`; `never` is deliberately inert — the
  approval layer only ADDS requirements and can never lower a tier),
  forcing ESCALATE via APR-001; ApprovalHistory as a read-only view over
  the existing audit chain, with a history line in the prompt ("rejected
  three times today" is information an approver should have);
  policy-configurable timeout that still resolves to DENY; and an
  escalation chain of askers for ABSENCE, never for overruling — an
  explicit human "no" stops the chain, only non-answers move to the next
  approver.
- `proxy/identity/sessions.py`: secure sessions — per-session workspace,
  the role's grants minted as signed tokens at open, v3 canary decoys
  planted automatically, open/close events on the main hash chain.
  `destroy()` revokes the issuer FIRST and then wipes the workspace, so
  even a failed wipe cannot leave a usable token behind; a closed session
  refuses everything, not as policy but because the key no longer exists.
- `proxy/identity/memguard.py`: memory integrity — append-only,
  HMAC-signed, hash-chained, versioned agent memory with a signed head
  file pinning chain length and tip. Tamper, reorder, insertion, and
  mid-store deletion are MEM-001; truncation/rollback against the pinned
  head is MEM-002; reads verify before they return and a bad chain raises
  rather than handing the agent poisoned state. Optional encryption at
  rest (Fernet) follows the Presidio contract: enabling it without the
  backend is a policy error at startup, never a silent downgrade.
- Engine + mediator integration: RBAC runs before tiers (a tool the
  identity layer forbids never reaches risk logic), capability checks run
  at the canonical-target stage, approval policies evaluate after risk
  accumulation, sessions thread through `mediate_call()`, and a closed
  session is refused before normalization. Policy validation rejects
  malformed `identity:` config at load.
- `tests/test_v4_identity_trust.py`: 64 tests — forgery, replay, expiry,
  revocation, scope stretching, RBAC intersection, approval-shopping
  prevention, session destruction, memory tamper/rollback, and the
  no-identity-block compatibility guarantee.

### Fixed
- **Memory verification was self-referential and could never pass** —
  found because a clean, just-written store failed its own integrity
  check: `put()` computes `this_hash` over the record before the hash
  field is attached, but verification recomputed it over the record WITH
  `this_hash` inside, so every store on earth failed MEM-001. The
  dangerous version of this bug is its "fix" — a verifier that never
  passes invites someone to weaken it until it does. Recomputation now
  excludes `this_hash` exactly as the write path does; the clean-store
  round-trip tests pin it.
- **Head-deletion rollback bypass** — found in review: rolling the store
  back AND deleting the head file produced an internally-valid chain with
  no rollback witness, so MEM-002 never fired. Every `put()` writes the
  head alongside the store, so a store with records and no head is itself
  a rollback signature and now raises MEM-002 — deleting the witness does
  not acquit the defendant. Pinned as a regression test.

## [3.0.0] — 2026-07-11

**v3 — Network Security.** Full control of outbound communication. The
minimal egress allowlist shipped in v1; this release completes the
subsystem: one ordered battery (`NetworkGuard.check_url`) that every
outbound URL faces — scheme, DNS sinkhole, global allowlist, per-tool
scope, reputation, SSRF resolve-then-validate — reused verbatim for every
redirect hop, so the engine and the redirect inspector cannot drift apart.
The entire subsystem runs against injectable resolvers: 90 new tests,
zero real network I/O.

### Added
- `proxy/network/guard.py`: the ordered battery. Per-tool egress scopes
  NARROW the global allowlist and can never widen it; sinkhole outranks
  allowlist so a configuration conflict resolves to the safe answer.
- `proxy/network/addrguard.py`: SSRF address classification. Cloud
  metadata endpoints (AWS/Azure/GCP/OpenStack, Alibaba, Oracle) are
  forbidden unconditionally; IPv4-mapped IPv6 is unwrapped so `::ffff:`
  dressing cannot slip a private v4 address past a v4-only check;
  loopback / link-local / private are policy-controlled and default to
  blocked. Invalid input classifies as a violation, never a pass.
- `proxy/network/dnspin.py`: resolve-then-validate with pinning. Every
  address in a DNS answer is validated — one bad address poisons the
  whole answer. A public-to-forbidden flip on a host that previously
  resolved clean is attributed as a DNS-rebinding signature (SSRF-002)
  distinct from an always-internal host (SSRF-001); pins expire so stale
  memory cannot mislabel. Resolution failure fails closed. The residual
  proxy-not-socket-owner TOCTOU window is documented, not papered over.
- `proxy/network/httpguard.py`: every redirect hop is a fresh network
  decision through the identical battery (HTTP-002), with a hop cap
  (HTTP-001); declared Content-Length and MIME type are the cheap early
  wall on the response side (HTTP-003/004) — declared headers can lie,
  which is why the download guard re-measures the actual payload.
- `proxy/network/downloads.py`: download guard — oversize (DL-001),
  executable magic bytes for PE/ELF/Mach-O (DL-002), zip bombs by
  declared expansion and compression ratio WITHOUT inflating the payload
  (DL-003), nested-archive depth and encrypted members (DL-004). Text
  payloads are judged on raw bytes AND any base64-decoded form, so a
  binary dressed as text is judged by what it decodes to.
- `proxy/network/reputation.py`: known-good / known-bad / unknown with
  TTL'd runtime cache and JSON persistence. known_bad denies even an
  allowlisted host; precedence bad > good > cache > unknown, so a host on
  both lists resolves to the safe answer. No third-party API calls — a
  gateway that phones home on every decision has added a trust boundary.
- `proxy/network/ratelimit.py`: in-process token buckets, global and
  per-tool (RATE-001). A call must clear BOTH; the tool bucket is checked
  first so a noisy tool exhausts its own budget before starving quiet
  tools. Injectable clock; no Redis until multi-node is real.
- `proxy/network/canary.py`: canary tokens (CAN-001, risk 100) — the only
  detector permitted to claim certainty, because its false-positive cost
  is structurally zero. `seed_workspace()` plants labeled decoys (.env,
  SSH-key-shaped, notes) whose fake values embed the marker, so partial
  exfiltration still trips the wire; the vault persists across sessions
  to catch the patient adversary.
- Engine + mediator integration: URL-bearing arguments run the battery in
  `decide()`; the mediator gains canary-before-everything and
  rate-limit-before-policy on the request path, `mediate_redirects()` on
  the redirect path, and header checks + download guard on the response
  path. Policy validation rejects malformed `network:` config at load.
- `tests/test_v3_network_security.py`: 90 tests, all resolvers injected,
  covering every battery rule, fail-closed path, and integration seam.

### Fixed
- **Escalate-masks-deny ordering flaw** — found by the new v3 suite on
  its first run: with `reputation.unknown_action: escalate`, the
  reputation check (step 5) returned REP-002 ESCALATE before the SSRF
  check (step 6) ever resolved the host. A reputation-unknown hostname
  whose DNS answer was the cloud metadata service produced a human
  approval prompt reading "no reputation record" instead of a hard SSRF
  deny — the human at the gate deciding on the wrong information. The
  battery now composes by severity: an escalate hint is held pending
  until the full battery has run and is returned only if nothing later
  demands a hard deny. Both directions are pinned as regression tests.

## [2.0.0] — 2026-07-11

**v2 — Model Security.** Defense-in-depth on top of v1 enforcement: expanded
adversarial-content detection, structural validation of tool calls, and a
MEASURED false-negative posture — every classifier scored against a labeled
attack corpus, miss rates published per class. Unmeasured detection is
unaccountable detection.

### Added
- `proxy/inspect/threats.py`: expanded detectors — role confusion (fake
  system/assistant turns, chat-template tokens), jailbreak scaffolds
  (DAN, developer-mode, "hypothetically"), hidden Unicode (Tags block,
  private-use, bidi override, invisible-character density), markup/HTML
  smuggling, and context-window abuse (oversized payloads, token flooding,
  excessive entropy). All emit the same `InjectionSignal` shape the v1
  inspector uses, so mediator/audit/policy need no changes.
- `proxy/inspect/schema.py`: JSON-Schema validation of tool CALLS and tool
  OUTPUTS. A `args_schema` declared on a tool means a call with the wrong
  structure is denied (rule SCHEMA-001) — deny-by-default stops unknown
  tools; this stops known tools invoked with a malformed shape. Dependency-
  free built-in validator covers the practical subset; the optional
  `jsonschema` package is used automatically if installed, never required.
- `proxy/inspect/evaluate.py` + `tests/corpus/attacks.py`: the measured
  posture harness. Runs every detector against 28 labeled synthetic attacks
  across six classes plus 10 benign decoys, reporting per-class recall, miss
  rate, and false positives. `python -m proxy.inspect.evaluate`.
- `docs/DETECTION_POSTURE.md`: published reference numbers and methodology —
  100% recall on the corpus, 0 false positives — with an explicit statement
  of what the measurement does and does not claim.
- v2 detectors wired into the mediator response path alongside the v1
  heuristics; `tests/test_v2_model_security.py` (23 tests) enforces a
  recall floor of 0.90 and zero benign false positives as a build gate.

### Fixed
- Detection gap found by the new posture harness on first run: an
  instruction-override phrasing with an intervening qualifier ("disregard
  the prior system prompt and follow these rules") slipped the v1 pattern.
  Pattern tightened; case pinned in the corpus.

## [1.5.5] — 2026-07-10

Optional Presidio detector backend — v1.5 phase complete.

### Added
- `proxy/inspect/presidio_backend.py`: opt-in adapter for richer PII
  detection (emails, phone numbers, national IDs, credit cards, IPs) behind
  the existing detector interface. Findings arrive in the same `Finding`
  shape with namespaced names (`presidio_email_address`, ...), so
  `redact()` and policy code work unchanged. Regex + entropy remain the
  always-on lightweight default; enabling presidio only ever ADDS findings.
- Enable with `redaction.detectors: [..., presidio]`;
  `pip install presidio-analyzer` plus a spaCy model. Zero import cost when
  not enabled.
- Fail loud, not silently weaker: policy validation rejects a policy that
  enables `presidio` when the backend cannot load — a security tool must
  never quietly downgrade the detection the operator configured. Also
  hardened against spaCy's model auto-downloader raising `SystemExit`.
- 8 tests (live-analysis tests skip cleanly when the optional dependency is
  absent; the fail-loud contract is tested everywhere).

### Fixed
- **`harden()` was not idempotent** — found in the field by the v1.5.2
  property suite (idempotence invariant) on a separate machine's fuzz run:
  an invisible character between a base letter and a combining mark blocks
  NFKC composition on the first pass; stripping the invisible then makes
  them adjacent, so a second pass composes them and the output changes
  ('a'+ZWSP+U+0308 -> 'a'+U+0308 -> 'ä'). A normalizer that changes on
  re-application is an evasion seam. `harden()` now iterates its pipeline to
  a fixpoint (bounded), and the exact payload class is pinned as a
  permanent regression test.

- **Windows: fake MCP server misdispatched canonical paths** — the test
  server extracted basenames with a '/'-only split, so Warden's canonical
  Windows paths (backslash separators) fell through to the generic handler
  and the redaction end-to-end test failed on Windows/Python 3.14. Fixed
  with a separator-agnostic basename; verified on Windows and Linux.

- **Windows: Warden's own generated policies were invalid YAML** — found in
  the field on Windows/Python 3.14 by the v1.5.4 CLI tests. Both the
  deny-all fallback and the `warden init` starter embedded OS-native paths
  in DOUBLE-quoted YAML scalars; in double-quoted YAML a backslash starts an
  escape sequence, so `C:\Users\...` produced a scanner error and Warden
  could not read the policy it had just written. Templates now use
  single-quoted scalars (backslash-literal by the YAML spec) and paths are
  emitted in POSIX form, valid on every OS. Additionally: a policy file
  that is not valid YAML now raises a clear `PolicyValidationError` instead
  of a raw scanner traceback, `warden stats --audit <path>` no longer
  touches any policy file at all, the generated fallback policy is
  gitignored, and the whole bug class is pinned by a parametrized
  regression suite (`tests/test_policy_paths.py`, 8 tests).

## [1.5.4] — 2026-07-10

Audit telemetry: the forensic log becomes an operational dashboard, with no
second bookkeeping system that could disagree with the tamper-evident record.
The log IS the source of truth; telemetry is a strictly read-only view.

### Added
- `proxy/audit/telemetry.py`: derives, from the audit log alone —
  allow/deny/escalate counts (normalized across writers), decisions by tool,
  highest-risk tools (average and max risk per tool), rule frequency,
  watchdog timeouts, injection detections, traversal attempts, secret
  blocks, egress denials, pinning events, and overall average risk.
- `warden stats` CLI command: rendered table or `--json` for tracking,
  `--top N` to bound listings, works against an explicit `--audit` path
  with no policy file present.
- 11 tests, including chain-intact-after-read verification and graceful
  handling of malformed detail rows.

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
