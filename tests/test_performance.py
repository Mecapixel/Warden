"""
tests/test_performance.py  (v1.5.3)

Performance regression guards. These are NOT benchmarks — benchmarks/bench.py
publishes the real numbers. These tests exist so an accidental O(n^2) in the
hot path fails CI instead of shipping.

Ceilings are deliberately generous (roughly 10-25x the measured medians in
docs/PERFORMANCE.md) so slow shared CI runners never flake, while a real
hot-path regression — the kind that turns microseconds into tens of
milliseconds — still trips the wire.
"""

import statistics
import time

import pytest

from warden.audit.log import AuditLog
from warden.core.request import Request
from warden.policy.engine import PolicyEngine
from warden.runtime.mediator import Mediator


N = 300


def _median_ms(fn, n=N) -> float:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.median(samples)


@pytest.fixture
def stack(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp_path}'\n"
        "mode: enforce\n"
        "tools:\n"
        "  read_file: {tier: auto, path_args: [path]}\n"
        "redaction: {enabled: true, detectors: [aws_keys, api_keys], block_secrets_in_args: true}\n"
    )
    engine = PolicyEngine(str(p))
    audit = AuditLog(str(tmp_path / "perf_audit.db"))
    yield engine, audit, Mediator(engine, audit)
    audit.close()


class TestPerformanceBudget:
    def test_normalize_budget(self, stack):
        med = _median_ms(
            lambda: Request.normalize("read_file", {"path": "a.txt"}).inspection_text())
        assert med < 1.0, f"normalize median {med:.3f} ms exceeds 1 ms budget"

    def test_policy_allow_budget(self, stack):
        engine, _, _ = stack
        req = Request.normalize("read_file", {"path": "a.txt"})
        med = _median_ms(lambda: engine.decide(req))
        assert med < 2.0, f"policy decide median {med:.3f} ms exceeds 2 ms budget"

    def test_policy_deny_is_not_slower_than_allow(self, stack):
        engine, _, _ = stack
        ok = Request.normalize("read_file", {"path": "a.txt"})
        bad = Request.normalize("launch_missiles", {})
        med_allow = _median_ms(lambda: engine.decide(ok))
        med_deny = _median_ms(lambda: engine.decide(bad))
        # Deny-by-default must stay effectively free: never pay MORE to say no.
        assert med_deny <= med_allow * 3, (
            f"deny path ({med_deny:.3f} ms) is anomalously slower than "
            f"allow path ({med_allow:.3f} ms)")

    def test_mediation_budget(self, stack):
        _, _, mediator = stack
        med = _median_ms(
            lambda: mediator.mediate_call("read_file", {"path": "a.txt"}), n=200)
        assert med < 20.0, f"mediation median {med:.3f} ms exceeds 20 ms budget"

    def test_audit_write_budget(self, stack):
        _, audit, _ = stack
        med = _median_ms(
            lambda: audit.record("read_file", "allow", "perf", {"t": 1}), n=200)
        assert med < 15.0, f"audit write median {med:.3f} ms exceeds 15 ms budget"
