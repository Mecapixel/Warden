# Warden Performance Budget

A security runtime too slow to leave on doesn't get run. This document
publishes Warden's measured overhead so it is a documented,
regression-tracked number instead of a guess. Reproduce anytime with:

```bash
python benchmarks/bench.py           # table
python benchmarks/bench.py --json    # machine-readable
```

## Measured (v1.5.3 reference run)

Single process, Linux, Python 3.12, SQLite audit on local disk,
n = 2,000 iterations per micro-stage, n = 60 live transport round trips.

| Stage | What it measures | Median | P95 | P99 |
|---|---|---|---|---|
| `normalize` | `Request.normalize()` + Unicode-hardened inspection view | 0.013 ms | 0.020 ms | 0.053 ms |
| `policy_allow` | full `PolicyEngine.decide()` on the allow path | 0.084 ms | 0.138 ms | 0.178 ms |
| `policy_deny` | `decide()` on the deny path (unknown tool) | 0.004 ms | 0.007 ms | 0.012 ms |
| `mediate_allow` | `Mediator.mediate_call()` end to end incl. audit write | 0.793 ms | 1.646 ms | 1.872 ms |
| `audit_write` | hash-chained `AuditLog.record()` (SQLite, WAL) | 0.557 ms | 0.690 ms | 4.032 ms |

**Live transport overhead** — a real `tools/call` round trip over real pipes,
fake MCP server called directly vs. through Warden (`warden run`):

| Path | Median RTT |
|---|---|
| client → server (direct) | 0.085 ms |
| client → **Warden** → server | 2.132 ms |
| **Warden overhead per mediated call** | **≈ 2.0 ms** |

**Memory:** ≈ 28 MiB peak RSS for the full benchmark process
(≈ 5 MiB attributable to engine + audit chain under load).

## Reading the numbers

- The deny path is the *cheapest* path (0.004 ms median): deny-by-default is
  effectively free, which is the right incentive structure for a security tool.
- Mediation cost is dominated by the durable audit write — the WAL commit is
  the price of a tamper-evident record, paid on every decision by design.
  The P99 spike on `audit_write` is fsync jitter, normal for durable SQLite.
- ~2 ms per tool call is the total tax an agent pays for full normalization,
  inspection, policy, and a court-usable audit trail. Typical tool calls
  (file I/O, network requests, model calls) run 10–10,000× that.

## Regression tracking

`tests/test_performance.py` enforces generous ceilings (≈10–25× the measured
medians) on every CI run — loose enough to never flake on slow shared
runners, tight enough that an accidental O(n²) in the hot path fails the
build rather than shipping.
