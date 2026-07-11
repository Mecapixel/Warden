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

## What's New (v1.5.5)

- **Audit Telemetry** — `warden stats` derives rich operational metrics directly from the tamper-evident log.
- **Optional Presidio Backend** — richer PII detection when available.
- **Improved Unicode Normalizer** — better homoglyph and control character handling.
- **200 passing tests** — expanded fuzzing and Windows compatibility fixes.

## Why

AI agents can be steered — by a malicious web page they scrape, a poisoned
document they read, or a crafted user prompt — into exfiltrating data, escaping
their workspace, or taking destructive actions. Warden puts a strong policy-enforcing
checkpoint between the untrusted actor and sensitive resources.

## What's Built (v1.5)

A working runtime, proven by a **200-test** synthetic attack, fuzz, and performance suite:

- Path canonicalization & workspace confinement
- Secret & PII redaction (arguments + responses)
- Indirect prompt-injection inspection
- Real MCP transport with watchdog
- Tool-definition pinning + drift detection
- Egress allowlisting
- Human approval gate with explainable decisions
- Fail-closed pipeline + monitor mode
- Tamper-evident hash-chained audit log
- Audit telemetry (`warden stats`)
- Optional Presidio PII backend
- Strong Unicode hardening

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full defense-to-threat mapping.

## Run it

```bash
python -m proxy.cli init                                  # starter policy + workspace
python -m proxy.cli inspect read_file '{"path": "a.txt"}' # one explained decision
python -m proxy.cli run -- <your-mcp-server-command>      # mediate a live server
python -m proxy.cli verify                                # audit-chain integrity
python -m proxy.cli stats                                 # operational telemetry