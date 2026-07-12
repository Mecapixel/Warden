# Warden

[![tests](https://github.com/Mecapixel/warden/actions/workflows/tests.yml/badge.svg)](https://github.com/Mecapixel/warden/actions/workflows/tests.yml)

**An explainable zero-trust security gateway for AI agents.**

Warden sits between an AI agent and the tools it can call, and enforces
security policy on every single tool call in real time. It exists because
agents are increasingly handed real capabilities — file systems, shells, APIs,
network access — with no firewall between the model and those tools. Warden
is that firewall.

Every tool call flows through the proxy and receives one of four decisions:

- **allow** — forward it unchanged
- **redact** — strip secrets/PII from arguments and responses, then forward
- **escalate** — pause and require a human yes/no
- **deny** — block it and return a safe error

The guiding principle is **deny by default**: a tool or path not explicitly
permitted by policy does not run.

## Why

AI agents can be steered — by a malicious web page they scrape, a poisoned
document they read, or a crafted user prompt — into exfiltrating data, escaping
their workspace, or taking destructive actions. Most guardrails today try to
make the *model* safer. Warden takes the complementary approach used
everywhere else in security: put a policy-enforcing checkpoint between the
untrusted actor and the sensitive resource, and log everything, tamper-evidently.

## What's built (v1 → v6)

A working runtime, proven by a 485-test synthetic attack, fuzz, and performance suite:

- **Path canonicalization** — blocks `../../etc/passwd`, absolute-path escapes,
  and symlink escapes; everything is confined to a workspace root.
- **Argument parameterization** — no shell strings, ever; `shell=False` argument
  vectors make command injection impossible by construction. (No shell tool is
  enabled in v1 by design; the guard exists so the safe path is the only path
  available when one is.)
- **Secret & PII screening, both directions** — credentials in tool arguments
  block the call outright; PII is flagged as risk and surfaced at the
  human-approval gate; tool *responses* pass through the redactor before they
  reach the agent's context.
- **Indirect prompt-injection inspection** — scans data returned *from* tools
  for hidden instructions before it reaches the agent's context, live in the
  transport (annotate / escalate / deny per policy).
- **Real MCP transport** — Warden physically between the client and a real MCP
  server (stdio JSON-RPC), with an execution watchdog, graceful drain, and
  generic errors to the agent (rule ids stay in the audit log, for the human).
- **Tool-definition pinning** — the trust boundary covers what a tool *is*,
  not just what it does. Tool schemas are canonicalized and SHA-256 hashed
  into a persistent, versioned registry at approval time; a server that swaps
  a tool's definition later (MCP rug-pull / tool poisoning) trips drift
  detection and is denied (rule PIN-001) until a human re-approves the new
  schema. Every register / approve / drift / reapprove event is on the audit
  chain.
- **Egress allowlist** — network destinations outside `egress.allowed_hosts`
  are denied; the exfiltration half of the injection kill chain dies here.
- **Human approval gate** — escalated actions pause for a yes/no on the
  terminal, with the full explainable decision shown; every failure mode
  (no terminal, timeout, error) resolves to DENY.
- **Fail-closed pipeline** — any internal failure becomes an audited DENY,
  proven by fault-injection tests; monitor mode (`mode: monitor`) computes and
  audits every decision without enforcing, for rollout and weight tuning.
- **Unicode hardening** — NFKC, zero-width/bidi stripping, and homoglyph
  folding run before every inspector, so lookalike characters cannot evade
  detection.
- **Tamper-evident audit log** — hash-chained record of every decision,
  independently verifiable with `warden verify`.
- **Audit telemetry** — `warden stats` derives operational metrics straight
  from the forensic log (verdict counts, highest-risk tools, rule frequency,
  watchdog/injection/traversal counters): one source of truth, read-only.
- **Optional Presidio backend** — opt-in richer PII detection behind the
  same detector interface; regex + entropy stay the always-on default, and a
  policy that enables presidio without the dependency present is rejected at
  startup rather than silently running weaker detection.
- **v2 model-security layer** — expanded adversarial detection (role
  confusion, jailbreak scaffolds, hidden Unicode, markup smuggling, context-
  window abuse), JSON-Schema validation of tool calls (rule SCHEMA-001), and
  a **measured** detection posture: every classifier scored against a
  labeled attack corpus with miss rates published per class
  ([`docs/DETECTION_POSTURE.md`](docs/DETECTION_POSTURE.md)). All
  defense-in-depth on top of v1 enforcement, never a replacement for it.
- **v3 network-security layer** — one ordered battery for every outbound
  URL (scheme, DNS sinkhole, global allowlist, per-tool scopes that narrow
  and never widen, domain reputation, SSRF resolve-then-validate with
  DNS-rebinding attribution), reused verbatim for every redirect hop; a
  download guard (executable magics, zip bombs judged without inflating
  them, nested/encrypted archives, base64-dressed binaries); token-bucket
  rate limiting; and canary tokens — the only detector permitted to claim
  certainty, because its false-positive cost is structurally zero. The
  whole subsystem runs against injectable resolvers: zero network I/O in
  its tests.
- **v4 identity & trust layer** — agent RBAC (the invoking user's role
  INTERSECTED with the deployment's scope, deny-by-default for unknown
  identities), HMAC-signed per-session capability tokens verified against
  canonical targets (single-use by default, replay refused, all revoked at
  the key when the session closes), per-capability approval policies with
  audit-chain history and escalation chains that cannot approval-shop,
  secure sessions that revoke keys BEFORE wiping workspaces, and signed,
  hash-chained, versioned agent memory with rollback pinning — tampering,
  truncation, and head-deletion all detected, reads verify before they
  return.
- **v5 runtime-containment layer** — the downstream MCP server runs inside
  a Warden-provisioned sandbox: the docker→gvisor→wasmtime isolation
  ladder with required-or-stronger selection (never a silent downgrade),
  an unbreachable floor (network none, read-only rootfs, cap-drop ALL,
  no-new-privileges), verified-destruction ephemeral workspaces, resource
  quotas validated at load with a host-held wall clock, and a process
  monitor for fork breaches, zombies, overstay, and unexpected
  executables. Rendered argv is the tested artifact — no container
  runtime needed to prove the posture.
- **v6 adaptive-security layer** — the payoff of monitor mode. Per-agent
  behavioral baselines learn each agent's normal and flag deviation
  (unfamiliar tool, unseen egress class, risk spike) as escalate hints,
  never autonomous denies; learning is gated, denied calls never teach
  "normal", and a suspect profile freezes. A user→agent→tool→file→network
  trust graph finds read-then-exfiltrate paths, privilege bridges, and
  blast radius no per-call guard can see. A read-only replay engine spends
  the recorded audit corpus to answer "what would this policy have done to
  the traffic we actually saw?" before rollout. Tighten-only adaptive
  controls — context floors, sticky human-clear-only quarantine, and intent
  verification against a stated goal — can only ever add caution, never
  lower a verdict below the static floor.
- **Tiered policy engine** — reads auto-allow, writes/deletes escalate to a
  human, dangerous tools denied; deny by default.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full defense-to-threat
mapping.

## Warden and the landscape

Prior art exists and is worth naming. Guardrails libraries and safety
classifiers (PromptGuard, Llama Guard) work at the model layer — they try to
detect bad content. MCP gateways and API proxies exist for routing and
observability. Warden's position is different on three axes: it is
**local-first** (your machine, your policy, no cloud dependency), it is
**deny-by-default runtime enforcement** rather than detection-only (a missed
detection still hits the policy wall), and every decision is **explainable
and audit-chained** (rule id, risk score, reason — verifiable after the
fact). Detection layers are welcome on top; they are defense-in-depth, never
the control. Warden assumes detection will sometimes fail and is built so
that failing detection does not mean failing open.

## Run it

```bash
python -m proxy.cli init                                  # starter policy + workspace
python -m proxy.cli inspect read_file '{"path": "a.txt"}' # one explained decision
python -m proxy.cli run -- <your-mcp-server-command>      # mediate a live server
python -m proxy.cli verify                                # audit-chain integrity
python -m proxy.cli stats                                 # operational telemetry
```

With no policy file present, Warden runs on a built-in deny-all default —
unconfigured Warden is a wall, not a hole.

## Run the tests

```bash
pip install -r requirements.txt
python -m pytest
```

Every test is a **synthetic, benign** attack payload — the structure of a real
attack with no destructive function. No real malware or live exploits exist in
this repository, by design.

## Honest status

**Built and tested (485 passing tests):** the full v1 pipeline — request
normalization, path canonicalization, safe-exec guarding, secret/PII detection
and response redaction, inbound-injection heuristics, risk scoring, the
explainable Decision object, the hash-chained audit log, real MCP stdio
transport with watchdog and fail-closed guarantees, the human approval gate,
monitor mode — plus v1.5 registry hardening (tool-definition pinning with
drift detection, Hypothesis fuzzing that found and fixed two relay-crash
vectors), v2 model security (measured detection posture with published
per-class miss rates), v3 network security (the full outbound battery, whose
first test run found and fixed an escalate-masks-deny ordering flaw), v4
identity & trust (whose review found and fixed a self-referential hash bug
and a head-deletion rollback bypass in memory verification), and v5 runtime
containment. Every phase is summarized in the What's built section above and
documented release by release in [`CHANGELOG.md`](CHANGELOG.md).
`python demo.py` exercises the decision core end to end;
`tests/test_transport.py` proves the full story over real pipes.

**Open, stated plainly:** no shell-style tool is enabled by design (the
safe-exec guard waits, armed). Detection is heuristic-plus-measured, not
ML — every classifier is scored against a labeled corpus with miss rates
published in [`docs/DETECTION_POSTURE.md`](docs/DETECTION_POSTURE.md), and
detection is defense-in-depth either way: the policy layer is the control
that prevents harm. Containment renders and audits hardened sandbox specs;
running them end to end against live Docker/gVisor/Wasmtime backends is
deployment work, not library work, and is stated as such. Measured overhead
is published in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md): ≈ 2 ms per mediated tool call
end to end, deny path effectively free. v1 through v6 are complete; v7
(the Warden platform — packaging, signed releases, and framework adapters)
is productization work, taken up only if this becomes real.

## License

AGPL-3.0 — the safeguards stay open and cannot be quietly stripped out.
