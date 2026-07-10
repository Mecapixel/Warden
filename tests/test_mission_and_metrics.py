"""
tests/test_mission_and_metrics.py

Tests for the v1-completion features: Mission Mode, the tool allowlist registry,
security metrics, and per-rule regression coverage.
"""

import pytest

from proxy.core.request import Request
from proxy.core.mission import Mission
from proxy.core.metrics import SecurityMetrics
from proxy.core.decision import Verdict
from proxy.policy.engine import PolicyEngine


@pytest.fixture
def engine(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp_path}'\n"
        "tool_registry: [read_file, list_directory, write_file, run_command]\n"
        "tools:\n"
        "  read_file: {tier: auto, inspect_response: true}\n"
        "  list_directory: {tier: auto}\n"
        "  write_file: {tier: escalate, inspect_args: true}\n"
        "  run_command: {tier: deny}\n"
        "redaction:\n"
        "  enabled: true\n"
        "  detectors: [aws_keys, api_keys]\n"
        "  block_secrets_in_args: true\n"
        "inbound_inspection: {enabled: true, on_injection_detected: escalate}\n"
    )
    return PolicyEngine(str(p))


# ---------------------------------------------------------------------------
# Mission Mode
# ---------------------------------------------------------------------------
class TestMissionMode:
    def test_action_within_mission_proceeds(self, engine):
        mission = Mission("Review my Python project", {"read_file", "list_directory"})
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"}), mission)
        assert d.verdict == Verdict.ALLOW

    def test_action_outside_mission_denied(self, engine):
        mission = Mission("Summarize a PDF", {"read_file"})
        # The agent tries to write — never part of a summarize mission.
        d = engine.decide(Request.normalize("write_file", {"path": "x.txt"}), mission)
        assert d.verdict == Verdict.DENY
        assert d.rule == "MIS-001"
        assert "outside the declared mission" in d.reason

    def test_mission_blocks_even_an_auto_tool(self, engine):
        # read_file is tier:auto, but if the mission doesn't include it, it's denied.
        mission = Mission("Only list files", {"list_directory"})
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"}), mission)
        assert d.verdict == Verdict.DENY
        assert d.rule == "MIS-001"

    def test_declared_mission_with_empty_allowlist_denies_everything(self, engine):
        # FAIL CLOSED: declaring a mission but forgetting the capability set
        # must deny everything, not silently grant everything. The only
        # abstaining mission is the explicit Mission.open() sentinel.
        mission = Mission("Review my project")  # declared, no tools listed
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"}), mission)
        assert d.verdict == Verdict.DENY
        assert d.rule == "MIS-001"

    def test_no_mission_abstains(self, engine):
        # With no mission, the normal tier rules apply (read_file allowed).
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"}))
        assert d.verdict == Verdict.ALLOW

    def test_mission_violation_scores_high_risk(self, engine):
        mission = Mission("Read only", {"read_file"})
        d = engine.decide(Request.normalize("write_file", {"path": "x.txt"}), mission)
        assert d.risk_score >= 50
        assert any(c["signal"] == "mission_violation" for c in d.risk_contributions)


# ---------------------------------------------------------------------------
# Tool allowlist registry
# ---------------------------------------------------------------------------
class TestToolRegistry:
    def test_unregistered_tool_denied(self, engine):
        # 'network_fetch' is not in tool_registry.
        d = engine.decide(Request.normalize("network_fetch", {"url": "http://x"}))
        assert d.verdict == Verdict.DENY
        assert d.rule == "REG-001"

    def test_registered_tool_proceeds(self, engine):
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"}))
        assert d.verdict == Verdict.ALLOW


# ---------------------------------------------------------------------------
# Security metrics
# ---------------------------------------------------------------------------
class TestMetrics:
    def test_metrics_accumulate(self, engine):
        m = SecurityMetrics()
        calls = [
            ("read_file", {"path": "a.txt"}),
            ("read_file", {"path": "../../etc/passwd"}),   # escape -> deny
            ("write_file", {"path": "x.txt", "content": "AKIAIOSFODNN7EXAMPLE"}),  # secret -> deny
            ("run_command", {"cmd": "ls"}),                # deny tier
        ]
        for tool, args in calls:
            m.record(engine.decide(Request.normalize(tool, args)))

        s = m.summary()
        assert s["total_requests"] == 4
        assert s["blocked"] >= 3
        assert s["filesystem_escapes"] >= 1
        assert s["secrets_caught"] >= 1
        assert 0 <= s["average_risk"] <= 100

    def test_render_is_readable(self, engine):
        m = SecurityMetrics()
        m.record(engine.decide(Request.normalize("read_file", {"path": "a.txt"})))
        text = m.render()
        assert "requests=1" in text
        assert "avg_risk=" in text


# ---------------------------------------------------------------------------
# Per-rule regression coverage — one test per rule id the engine can emit.
# If a refactor changes which rule fires for a canonical case, these catch it.
# ---------------------------------------------------------------------------
class TestRuleRegression:
    def test_MIS_001_mission_violation(self, engine):
        m = Mission("read only", {"read_file"})
        assert engine.decide(Request.normalize("write_file", {"path": "x"}), m).rule == "MIS-001"

    def test_REG_001_unregistered_tool(self, engine):
        assert engine.decide(Request.normalize("ftp_send", {})).rule == "REG-001"

    def test_TOOL_002_deny_tier(self, engine):
        assert engine.decide(Request.normalize("run_command", {"cmd": "ls"})).rule == "TOOL-002"

    def test_FS_004_path_escape(self, engine):
        assert engine.decide(Request.normalize("read_file", {"path": "../../etc/passwd"})).rule == "FS-004"

    def test_SEC_001_secret_in_args(self, engine):
        d = engine.decide(Request.normalize("write_file", {"path": "x", "content": "AKIAIOSFODNN7EXAMPLE"}))
        assert d.rule == "SEC-001"

    def test_TOOL_003_escalate(self, engine):
        assert engine.decide(Request.normalize("write_file", {"path": "ok.txt"})).rule == "TOOL-003"

    def test_TOOL_004_allow(self, engine):
        assert engine.decide(Request.normalize("read_file", {"path": "ok.txt"})).rule == "TOOL-004"
