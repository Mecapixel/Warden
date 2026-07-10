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

## What's built (v1 + v1.5.1)

A working runtime, proven by a 167-test synthetic attack and fuzz suite:

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

**Built and tested (167 passing tests):** the full v1 pipeline — request
normalization, path canonicalization, safe-exec guarding, secret/PII detection
and response redaction, inbound-injection heuristics, risk scoring, the
explainable Decision object, the hash-chained audit log, real MCP stdio
transport with watchdog and fail-closed guarantees, the minimal egress
allowlist, the human approval gate, monitor mode — plus v1.5.1
tool-definition pinning with drift detection and reapproval, and v1.5.2
Hypothesis fuzz and property testing of the Normalize boundary — which found
and fixed two relay-crash vectors (deep-nesting JSON bombs, non-object
top-level JSON) now locked in by a fail-closed line parser.
`python demo.py` exercises the decision core end to end;
`tests/test_transport.py` proves the full story over real pipes.

**Open, stated plainly:** no shell-style tool is enabled by design (the
safe-exec guard waits, armed). The inbound-injection scanner is a regex
heuristic — a first-pass filter, not a classifier; that upgrade is v2, and
detection is defense-in-depth either way: the policy layer is the control
that prevents harm. Next up: a measured performance budget, audit telemetry derived
from the log, and an optional Presidio detector backend.

## License

AGPL-3.0 — the safeguards stay open and cannot be quietly stripped out.
