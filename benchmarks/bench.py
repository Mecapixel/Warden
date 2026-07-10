"""
benchmarks/bench.py  (v1.5.3)

Warden performance budget. Measures every stage a request pays for, so the
runtime's overhead is a documented, regression-tracked number instead of a
guess. A security runtime too slow to leave on doesn't get run.

Stages measured (median / P95 / P99, wall-clock, single process):

  normalize        Request.normalize() + inspection_text()  (Unicode hardening)
  policy_allow     PolicyEngine.decide() on the auto-allow path
  policy_deny      PolicyEngine.decide() on the deny path (unknown tool)
  mediate_allow    Mediator.mediate_call() end to end incl. audit write
  audit_write      AuditLog.record() alone (hash-chain + SQLite WAL commit)
  transport_rtt    full round trip through the live MCP proxy against the
                   fake server over real pipes, minus the fake server's own
                   direct-call time = Warden's per-call transport overhead

Memory: peak RSS delta across the run (resource.getrusage).

Run:
    python benchmarks/bench.py            # human-readable table
    python benchmarks/bench.py --json     # machine-readable, for tracking
"""

import argparse
import json
import resource
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxy.core.request import Request
from proxy.policy.engine import PolicyEngine
from proxy.audit.log import AuditLog
from proxy.runtime.mediator import Mediator

N = 2000            # iterations per micro-stage
N_TRANSPORT = 60    # round trips through the live proxy


def _timeit(fn, n=N) -> dict:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)  # ms
    samples.sort()
    return {
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 4),
        "p99_ms": round(samples[int(len(samples) * 0.99) - 1], 4),
        "n": n,
    }


def _make_engine(tmp: Path) -> PolicyEngine:
    p = tmp / "policy.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp}'\n"
        "mode: enforce\n"
        "tools:\n"
        "  read_file: {tier: auto, path_args: [path]}\n"
        "redaction: {enabled: true, detectors: [aws_keys, api_keys], block_secrets_in_args: true}\n"
    )
    return PolicyEngine(str(p))


def bench_micro(tmp: Path) -> dict:
    engine = _make_engine(tmp)
    audit = AuditLog(str(tmp / "bench_audit.db"))
    mediator = Mediator(engine, audit)

    results = {}
    args = {"path": "notes/a.txt"}

    results["normalize"] = _timeit(
        lambda: Request.normalize("read_file", args).inspection_text())

    req_ok = Request.normalize("read_file", args)
    results["policy_allow"] = _timeit(lambda: engine.decide(req_ok))

    req_bad = Request.normalize("launch_missiles", {})
    results["policy_deny"] = _timeit(lambda: engine.decide(req_bad))

    results["mediate_allow"] = _timeit(
        lambda: mediator.mediate_call("read_file", args))

    results["audit_write"] = _timeit(
        lambda: audit.record("read_file", "allow", "bench", {"bench": True}))

    audit.close()
    return results


def bench_transport(tmp: Path) -> dict | None:
    """Best-effort transport RTT: spawn the fake MCP server under the proxy,
    issue N_TRANSPORT tools/call round trips, time them. Skipped (returns
    None) if the sandbox can't spawn subprocesses."""
    import asyncio
    from proxy.transport.mcp import MCPProxy, parse_jsonrpc_line
    from proxy.core.mission import Mission

    engine = _make_engine(tmp)
    audit = AuditLog(str(tmp / "bench_transport_audit.db"))
    mediator = Mediator(engine, audit)

    fake_server = [sys.executable, str(Path(__file__).resolve().parent.parent
                                       / "tests" / "fake_mcp_server.py")]

    async def run() -> dict | None:
        proc = await asyncio.create_subprocess_exec(
            *fake_server,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

        async def call(i: int) -> float:
            msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                   "params": {"name": "read_file",
                              "arguments": {"path": "notes/a.txt"}}}
            t0 = time.perf_counter()
            proc.stdin.write((json.dumps(msg) + "\n").encode())
            await proc.stdin.drain()
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=10)
                reply = parse_jsonrpc_line(line.strip())
                if reply and reply.get("id") == i:
                    return (time.perf_counter() - t0) * 1000.0

        # Direct path: client -> fake server, no Warden.
        direct = []
        for i in range(N_TRANSPORT):
            direct.append(await call(i))
        proc.stdin.close()
        await proc.wait()

        # Mediated path: client -> Warden -> fake server.
        # MCPProxy relays our stdin/stdout, so run it as a subprocess of this
        # process the same way `warden run` does: python -m proxy.cli run.
        wproc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "proxy.cli", "--policy",
            str(tmp / "policy.yaml"), "run", "--audit",
            str(tmp / "bench_transport_audit2.db"), "--", *fake_server,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            cwd=str(Path(__file__).resolve().parent.parent),
        )

        async def wcall(i: int) -> float:
            msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                   "params": {"name": "read_file",
                              "arguments": {"path": "notes/a.txt"}}}
            t0 = time.perf_counter()
            wproc.stdin.write((json.dumps(msg) + "\n").encode())
            await wproc.stdin.drain()
            while True:
                line = await asyncio.wait_for(wproc.stdout.readline(), timeout=10)
                reply = parse_jsonrpc_line(line.strip())
                if reply and reply.get("id") == i:
                    return (time.perf_counter() - t0) * 1000.0

        mediated = []
        for i in range(N_TRANSPORT):
            mediated.append(await wcall(i))
        wproc.stdin.close()
        await wproc.wait()

        direct.sort(); mediated.sort()
        med_d = statistics.median(direct)
        med_m = statistics.median(mediated)
        return {
            "direct_median_ms": round(med_d, 3),
            "mediated_median_ms": round(med_m, 3),
            "mediated_p95_ms": round(mediated[int(len(mediated) * .95) - 1], 3),
            "warden_overhead_median_ms": round(med_m - med_d, 3),
            "n": N_TRANSPORT,
        }

    try:
        return asyncio.run(run())
    except Exception as e:  # sandboxed environments without subprocess, etc.
        print(f"  transport benchmark skipped: {e!r}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-transport", action="store_true")
    opts = ap.parse_args()

    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        results = bench_micro(tmp)
        if not opts.no_transport:
            t = bench_transport(tmp)
            if t:
                results["transport_rtt"] = t

    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is KiB on Linux.
    results["_memory"] = {"peak_rss_delta_mib": round((rss_after - rss_before) / 1024, 1),
                          "peak_rss_mib": round(rss_after / 1024, 1)}

    if opts.json:
        print(json.dumps(results, indent=2))
        return

    print("\nWarden performance budget")
    print("=" * 64)
    for stage, r in results.items():
        if stage.startswith("_") or stage == "transport_rtt":
            continue
        print(f"{stage:<16} median {r['median_ms']:>8.4f} ms   "
              f"P95 {r['p95_ms']:>8.4f} ms   P99 {r['p99_ms']:>8.4f} ms   (n={r['n']})")
    if "transport_rtt" in results:
        t = results["transport_rtt"]
        print("-" * 64)
        print(f"{'transport_rtt':<16} direct {t['direct_median_ms']} ms  ->  "
              f"mediated {t['mediated_median_ms']} ms  "
              f"(overhead {t['warden_overhead_median_ms']} ms, n={t['n']})")
    m = results["_memory"]
    print("-" * 64)
    print(f"peak RSS {m['peak_rss_mib']} MiB  (delta {m['peak_rss_delta_mib']} MiB)")
    print()


if __name__ == "__main__":
    main()
