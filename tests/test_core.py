"""
tests/test_core.py

Tests for the v1 core additions: request normalization, risk scoring, and the
explainable Decision object. These verify not just the verdict but the *why* —
that every decision carries a rule id, a risk score, contributors, and a fix.
"""

import pytest

from warden.core.request import Request
from warden.core.risk import RiskAssessment, RISK_WEIGHTS
from warden.core.decision import Decision, Verdict
from warden.policy.engine import PolicyEngine


# ---------------------------------------------------------------------------
# Request normalization
# ---------------------------------------------------------------------------
class TestRequestNormalization:
    def test_normalize_assigns_id_and_timestamp(self):
        r = Request.normalize("filesystem.read", {"path": "a.txt"})
        assert r.tool == "filesystem.read"
        assert r.args == {"path": "a.txt"}
        assert r.request_id           # a UUID was assigned
        assert r.received_at          # a timestamp was stamped
        assert r.user == "anonymous"  # default identity

    def test_two_requests_have_distinct_ids(self):
        a = Request.normalize("t", {})
        b = Request.normalize("t", {})
        assert a.request_id != b.request_id


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
class TestRiskScoring:
    def test_empty_assessment_scores_zero_and_allows(self):
        a = RiskAssessment()
        assert a.score == 0
        assert a.band == "allow"

    def test_single_hard_boundary_forces_deny(self):
        a = RiskAssessment()
        a.add("filesystem_escape", "path escapes workspace")
        assert a.score == RISK_WEIGHTS["filesystem_escape"]
        assert a.band == "deny"

    def test_soft_signals_accumulate_to_escalate(self):
        a = RiskAssessment()
        a.add("prompt_injection", "override phrasing seen")   # 15
        a.add("output_leak", "email in response")             # 10
        assert a.score == 25
        assert a.band == "escalate"

    def test_score_capped_at_100(self):
        a = RiskAssessment()
        a.add("filesystem_escape", "x")
        a.add("shell_injection", "y")
        assert a.score == 100  # 60 + 60 capped

    def test_top_reason_reports_highest_contributor(self):
        a = RiskAssessment()
        a.add("output_leak", "minor leak")
        a.add("filesystem_escape", "the big one")
        assert a.top_reason() == "the big one"


# ---------------------------------------------------------------------------
# Explainable decisions
# ---------------------------------------------------------------------------
class TestExplainability:
    @pytest.fixture
    def engine(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools:\n"
            "  read_file: {tier: auto, inspect_response: true}\n"
            "  write_file: {tier: escalate, inspect_args: true}\n"
            "  run_command: {tier: deny}\n"
            "redaction:\n"
            "  enabled: true\n"
            "  detectors: [aws_keys, api_keys]\n"
            "  block_secrets_in_args: true\n"
            "inbound_inspection: {enabled: true, on_injection_detected: escalate}\n"
        )
        return PolicyEngine(str(p))

    def test_traversal_decision_is_fully_explained(self, engine):
        d = engine.decide(Request.normalize("read_file", {"path": "../../etc/passwd"}))
        assert d.verdict == Verdict.DENY
        assert d.rule == "FS-004"                     # cites the exact rule
        assert d.risk_score >= 60                     # hard-boundary weight
        assert d.recommended_fix                      # tells the user how to fix
        assert d.target == "../../etc/passwd"
        assert any(c["signal"] == "filesystem_escape" for c in d.risk_contributions)

    def test_explain_renders_full_block(self, engine):
        d = engine.decide(Request.normalize("read_file", {"path": "../../etc/passwd"}))
        text = d.explain()
        assert "Decision: DENY" in text
        assert "Rule:" in text
        assert "Risk:" in text
        assert "Fix:" in text

    def test_allow_carries_rule_and_zero_risk(self, engine):
        d = engine.decide(Request.normalize("read_file", {"path": "notes.txt"}))
        assert d.verdict == Verdict.ALLOW
        assert d.rule == "TOOL-004"
        assert d.risk_score == 0

    def test_unknown_tool_explained_as_deny_by_default(self, engine):
        d = engine.decide(Request.normalize("format_disk", {}))
        assert d.verdict == Verdict.DENY
        assert d.rule == "TOOL-001"
        assert "deny by default" in d.reason.lower()

    def test_secret_in_args_explained(self, engine):
        d = engine.decide(Request.normalize("write_file",
                                            {"path": "x.txt", "content": "AKIAIOSFODNN7EXAMPLE"}))
        assert d.verdict == Verdict.DENY
        assert d.rule == "SEC-001"
        assert any(c["signal"] == "secret_in_transit" for c in d.risk_contributions)
