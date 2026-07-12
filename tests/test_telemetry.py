"""
tests/test_telemetry.py  (v1.5.4)

The forensic audit log becomes an operational dashboard. These tests write a
scripted history into a real AuditLog, then assert that every roadmap metric
is derived correctly: verdict counts, decisions by tool, highest-risk tools,
rule frequency, watchdog events, injection detections, traversal attempts,
and average risk. Telemetry is a read-only view — nothing here mutates the
log, and the chain must verify before and after.
"""

import json

import pytest

from warden.audit.log import AuditLog
from warden.audit.telemetry import snapshot, render


@pytest.fixture
def populated_log(tmp_path):
    path = str(tmp_path / "telemetry_audit.db")
    log = AuditLog(path)
    # A day in the life: mixed verdicts, rules, risks, and transport events.
    log.record("read_file", "allow", "ok", {"rule": "TOOL-004", "risk": 0})
    log.record("read_file", "allow", "ok", {"rule": "TOOL-004", "risk": 10})
    log.record("write_file", "escalate", "human gate", {"rule": "TOOL-003", "risk": 40})
    log.record("read_file", "deny", "path escape", {"rule": "FS-004", "risk": 100})
    log.record("http_get", "deny", "egress blocked", {"rule": "EGR-001", "risk": 80})
    log.record("write_file", "deny", "secret in args", {"rule": "SEC-001", "risk": 90})
    log.record("launch_missiles", "deny", "unknown tool", {"rule": "TOOL-001", "risk": 60})
    log.record("slow_tool", "DENY", "watchdog timeout", {"rule": "WDG-001"})
    log.record("web_search", "INJECTION_SIGNAL", "heuristic fired",
               {"top_pattern": "ignore previous", "severity": 3})
    log.record("evil_tool", "PIN_DRIFT", "definition changed",
               {"verdict": "drifted"})
    log.record("evil_tool", "DENY", "pinning", {"rule": "PIN-001"})
    yield path, log
    log.close()


class TestTelemetrySnapshot:
    def test_totals_and_verdict_counts(self, populated_log):
        path, _ = populated_log
        r = snapshot(path)
        assert r["total_events"] == 11
        assert r["verdict_counts"]["allow"] == 2
        assert r["verdict_counts"]["escalate"] == 1
        # 'deny' + transport 'DENY' normalize into one bucket: 4 + 2 = 6
        assert r["verdict_counts"]["deny"] == 6

    def test_specialized_counters(self, populated_log):
        path, _ = populated_log
        r = snapshot(path)
        assert r["watchdog_events"] == 1
        assert r["injection_detections"] == 1
        assert r["traversal_attempts"] == 1
        assert r["secret_blocks"] == 1
        assert r["egress_denials"] == 1
        assert r["pinning_events"].get("PIN-001") == 1
        assert r["pinning_events"].get("pin_drift") == 1

    def test_rule_frequency(self, populated_log):
        path, _ = populated_log
        r = snapshot(path)
        assert r["rule_frequency"]["TOOL-004"] == 2
        assert r["rule_frequency"]["FS-004"] == 1
        assert r["rule_frequency"]["WDG-001"] == 1

    def test_by_tool_and_average_risk(self, populated_log):
        path, _ = populated_log
        r = snapshot(path)
        assert r["by_tool"]["read_file"]["allow"] == 2
        assert r["by_tool"]["read_file"]["deny"] == 1
        assert r["by_tool"]["read_file"]["total"] == 3
        # risks recorded: 0,10,40,100,80,90,60 -> avg 54.3
        assert r["average_risk"] == pytest.approx(54.3, abs=0.1)

    def test_top_risk_tools_ordering(self, populated_log):
        path, _ = populated_log
        r = snapshot(path)
        top = r["top_risk_tools"]
        assert top[0]["tool"] in ("write_file", "http_get")  # avg 65 vs 80
        assert top[0]["avg_risk"] >= top[-1]["avg_risk"]
        rf = next(t for t in top if t["tool"] == "read_file")
        assert rf["avg_risk"] == pytest.approx(36.7, abs=0.1)
        assert rf["max_risk"] == 100

    def test_read_only_view_chain_still_intact(self, populated_log):
        path, log = populated_log
        snapshot(path)
        snapshot(path)
        assert log.verify_chain() is True

    def test_empty_log(self, tmp_path):
        path = str(tmp_path / "empty.db")
        AuditLog(path).close()
        r = snapshot(path)
        assert r["total_events"] == 0
        assert r["verdict_counts"] == {"allow": 0, "deny": 0, "escalate": 0}
        assert r["average_risk"] == 0.0
        assert "TELEMETRY" in render(r)

    def test_malformed_detail_does_not_crash(self, tmp_path):
        path = str(tmp_path / "weird.db")
        log = AuditLog(path)
        log.record("t", "allow", "ok", {"rule": "TOOL-004"})
        # Sneak a malformed detail row in directly (simulating corruption of
        # a non-hashed read path — telemetry must degrade, not die).
        import sqlite3
        conn = sqlite3.connect(path)
        conn.execute(
            "INSERT INTO audit (event_id, parent_event_id, ts, tool, decision,"
            " reason, detail, prev_hash, entry_hash)"
            " VALUES ('x', NULL, 1.0, 't2', 'deny', 'r', '{not json', 'p', 'h')")
        conn.commit(); conn.close()
        r = snapshot(path)
        assert r["total_events"] == 2
        assert r["verdict_counts"]["deny"] == 1
        log.close()


class TestTelemetryCLI:
    def test_stats_json(self, populated_log, capsys):
        path, _ = populated_log
        from warden.cli import build_parser
        args = build_parser().parse_args(["stats", "--audit", path, "--json"])
        assert args.func(args) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["total_events"] == 11
        assert out["watchdog_events"] == 1

    def test_stats_table(self, populated_log, capsys):
        path, _ = populated_log
        from warden.cli import build_parser
        args = build_parser().parse_args(["stats", "--audit", path])
        assert args.func(args) == 0
        text = capsys.readouterr().out
        assert "WARDEN AUDIT TELEMETRY" in text
        assert "injection detections  1" in text

    def test_stats_missing_log(self, tmp_path, capsys):
        from warden.cli import build_parser
        args = build_parser().parse_args(
            ["stats", "--audit", str(tmp_path / "nope.db")])
        assert args.func(args) == 2
