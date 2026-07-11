"""
tests/test_presidio.py  (v1.5.5)

The optional Presidio backend. Contract under test:
  * Opt-in and additive: enabling 'presidio' ADDS richer PII findings; the
    regex + entropy detectors still fire exactly as before.
  * Same Finding shape, namespaced detector names (presidio_*), so redact()
    works unchanged.
  * Fail loud, not silently weaker: a policy that enables 'presidio' when
    the backend cannot load is REJECTED at validation time.

The live-analysis tests skip cleanly when presidio isn't installed (it is an
optional dependency by design); the fail-loud policy test runs everywhere.
"""

import pytest

from proxy.inspect import presidio_backend, redactor
from proxy.policy.engine import PolicyEngine, PolicyValidationError

_ok, _why = presidio_backend.available()
needs_presidio = pytest.mark.skipif(
    not _ok, reason=f"presidio backend unavailable: {_why}")


# ---------------------------------------------------------------------------
# Fail-loud policy validation — runs with or without presidio installed
# ---------------------------------------------------------------------------

class TestFailLoudPolicy:
    def test_policy_rejected_when_backend_unavailable(self, tmp_path, monkeypatch):
        monkeypatch.setattr(presidio_backend, "available",
                            lambda: (False, "ImportError('presidio_analyzer')"))
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools: {read_file: {tier: auto}}\n"
            "redaction: {enabled: true, detectors: [aws_keys, presidio]}\n"
        )
        with pytest.raises(PolicyValidationError, match="presidio"):
            PolicyEngine(str(p))

    def test_policy_without_presidio_unaffected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(presidio_backend, "available",
                            lambda: (False, "ImportError('presidio_analyzer')"))
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools: {read_file: {tier: auto}}\n"
            "redaction: {enabled: true, detectors: [aws_keys, api_keys]}\n"
        )
        PolicyEngine(str(p))  # must not raise

    @needs_presidio
    def test_policy_accepted_when_backend_available(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools: {read_file: {tier: auto}}\n"
            "redaction: {enabled: true, detectors: [aws_keys, presidio]}\n"
        )
        PolicyEngine(str(p))  # must not raise


# ---------------------------------------------------------------------------
# Live analysis — skipped when the optional dependency is absent
# ---------------------------------------------------------------------------

@needs_presidio
class TestPresidioDetection:
    def test_finds_email_with_namespaced_detector(self):
        findings = presidio_backend.scan_presidio(
            "please reach me at victim.contact@example.com about the case")
        kinds = {f.detector for f in findings}
        assert "presidio_email_address" in kinds
        f = next(x for x in findings if x.detector == "presidio_email_address")
        assert f.match == "victim.contact@example.com"

    def test_additive_via_redactor_scan(self):
        text = ("api token AKIAIOSFODNN7EXAMPLE and email "
                "someone@example.org in the same payload")
        base = redactor.scan(text, ["aws_keys"])
        combined = redactor.scan(text, ["aws_keys", "presidio"])
        base_kinds = {f.detector for f in base}
        combined_kinds = {f.detector for f in combined}
        assert "aws_keys" in base_kinds
        assert base_kinds <= combined_kinds          # nothing removed
        assert "presidio_email_address" in combined_kinds  # richer PII added

    def test_redact_masks_presidio_findings(self):
        text = "forward this to journalist.tip@example.net today"
        red, findings = redactor.redact(text, ["presidio"])
        assert "journalist.tip@example.net" not in red
        assert any(f.detector.startswith("presidio_") for f in findings)

    def test_empty_and_clean_text(self):
        assert presidio_backend.scan_presidio("") == []
        clean = presidio_backend.scan_presidio("read the file and summarize it")
        assert all(f.detector.startswith("presidio_") for f in clean)

    def test_min_score_filters(self):
        text = "call 212-555-0147 now"
        low = presidio_backend.scan_presidio(text, min_score=0.1)
        high = presidio_backend.scan_presidio(text, min_score=0.99)
        assert len(high) <= len(low)
