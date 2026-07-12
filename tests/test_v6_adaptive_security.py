"""
tests/test_v6_adaptive_security.py

v6 — Adaptive Security. Behavioral baselines that learn normal and flag
deviation without ever deciding guilt; a trust graph that finds
read-then-exfiltrate paths, privilege bridges, and blast radius that no
per-call guard can see; a replay engine that answers "what would this policy
have done to the traffic we actually saw?" read-only and side-effect-free;
and the adaptive controls (context floors, sticky quarantine, intent
verification) that share one law — context can only ADD caution.

The through-line asserted everywhere: nothing here DENIES on its own. Every
learned or contextual signal is an escalate-or-tighten hint; the static
policy floor remains the control.
"""

import json

import pytest

from proxy.adaptive.behavior import BehaviorBaseline, AgentProfile
from proxy.adaptive.trustgraph import (
    TrustGraph, Node, USER, AGENT, TOOL, FILE, NETWORK)
from proxy.adaptive.replay import ReplayEngine, simulate
from proxy.adaptive.policy import (
    AdaptivePolicy, ContextRule, Quarantine, IntentVerifier)
from proxy.core.decision import Verdict
from proxy.policy.engine import PolicyEngine, PolicyValidationError


# ---------------------------------------------------------------------------
# Behavioral baseline
# ---------------------------------------------------------------------------
def warm(baseline, agent, tool="filesystem.read", n=None, risk=10,
         host_class=None):
    n = n if n is not None else baseline.warmup
    for _ in range(n):
        baseline.observe(agent, tool, "ALLOW", risk, host_class=host_class)


class TestBehaviorBaseline:
    def test_silent_during_warmup(self):
        b = BehaviorBaseline({"warmup_calls": 30})
        warm(b, "agent-a", n=10)                      # under warmup
        assert b.score("agent-a", "network.egress", risk=90) == []

    def test_novel_tool_flagged_after_warmup(self):
        b = BehaviorBaseline({"warmup_calls": 20})
        warm(b, "agent-a", tool="filesystem.read", n=20)
        anomalies = b.score("agent-a", "network.egress", risk=10)
        assert any(a.rule == "ANOM-001" for a in anomalies)

    def test_known_tool_not_flagged(self):
        b = BehaviorBaseline({"warmup_calls": 20})
        warm(b, "agent-a", tool="filesystem.read", n=20)
        assert b.score("agent-a", "filesystem.read", risk=10) == []

    def test_novel_host_class_flagged(self):
        b = BehaviorBaseline({"warmup_calls": 10})
        warm(b, "agent-a", tool="http_get", n=10, host_class="public")
        anomalies = b.score("agent-a", "http_get", risk=10, host_class="internal")
        assert any(a.rule == "ANOM-002" for a in anomalies)

    def test_risk_spike_flagged(self):
        b = BehaviorBaseline({"warmup_calls": 10, "risk_spike_margin": 30})
        warm(b, "agent-a", n=10, risk=20)             # ceiling 20
        anomalies = b.score("agent-a", "filesystem.read", risk=80)
        assert any(a.rule == "ANOM-003" for a in anomalies)

    def test_risk_within_margin_not_flagged(self):
        b = BehaviorBaseline({"warmup_calls": 10, "risk_spike_margin": 30})
        warm(b, "agent-a", n=10, risk=20)
        assert b.score("agent-a", "filesystem.read", risk=45) == []

    def test_denied_calls_do_not_teach_normal(self):
        # A denied call must NOT become an example of good behavior — else an
        # attacker's rejected probes would train the baseline to accept them.
        b = BehaviorBaseline({"warmup_calls": 5})
        for _ in range(10):
            b.observe("agent-a", "exec", "DENY", risk=95)
        warm(b, "agent-a", tool="filesystem.read", n=5)
        # exec never entered the profile despite 10 observations of it
        assert "exec" not in b.profile("agent-a").tools
        assert any(a.rule == "ANOM-001" for a in b.score("agent-a", "exec", risk=95))

    def test_frozen_profile_stops_learning_keeps_judging(self):
        b = BehaviorBaseline({"warmup_calls": 5})
        warm(b, "agent-a", tool="filesystem.read", n=5)
        b.freeze("agent-a")
        # further observations do NOT expand the profile...
        b.observe("agent-a", "network.egress", "ALLOW", risk=10, host_class="public")
        assert "network.egress" not in b.profile("agent-a").tools
        # ...and it still scores against the pre-freeze baseline
        assert any(a.rule == "ANOM-001"
                   for a in b.score("agent-a", "network.egress", risk=10))

    def test_profile_round_trips_through_json(self):
        b = BehaviorBaseline({"warmup_calls": 5})
        warm(b, "agent-a", n=5, host_class="public")
        blob = b.profile("agent-a").to_json()
        restored = AgentProfile.from_json(blob)
        assert restored.agent_id == "agent-a" and restored.calls == 5

    def test_negative_warmup_refused(self):
        with pytest.raises(ValueError):
            BehaviorBaseline({"warmup_calls": -1})

    def test_baseline_never_returns_a_verdict(self):
        # Structural guarantee: score() yields Anomaly objects carrying
        # POINTS, never a Verdict. Deviation is not guilt.
        b = BehaviorBaseline({"warmup_calls": 1})
        warm(b, "agent-a", n=1)
        for a in b.score("agent-a", "network.egress", risk=99):
            assert isinstance(a.severity, int)
            assert not isinstance(a.severity, Verdict)


# ---------------------------------------------------------------------------
# Trust graph
# ---------------------------------------------------------------------------
class TestTrustGraph:
    def test_read_then_exfiltrate_path_found(self):
        g = TrustGraph()
        agent = Node(AGENT, "a1")
        badfile = Node(FILE, "/untrusted/notes.md")
        egress = Node(NETWORK, "attacker.example")
        g.add_edge(agent, badfile, "reads")
        g.add_edge(agent, egress, "egresses")
        g.mark_untrusted(badfile)
        g.mark_sink(egress)
        # The taint travels: file -> (agent read it) -> agent -> egress.
        g.add_edge(badfile, agent, "taints")
        findings = g.taint_paths()
        assert any(f.rule == "TG-001" for f in findings)
        f = next(f for f in findings if f.rule == "TG-001")
        assert str(egress) in f.path and str(badfile) == f.path[0]

    def test_clean_graph_has_no_taint_path(self):
        g = TrustGraph()
        agent = Node(AGENT, "a1")
        goodfile = Node(FILE, "/workspace/data.csv")
        egress = Node(NETWORK, "api.example.com")
        g.add_edge(agent, goodfile, "reads")
        g.add_edge(agent, egress, "egresses")
        g.mark_sink(egress)                    # no untrusted source marked
        assert g.taint_paths() == []

    def test_taint_path_is_cycle_safe(self):
        g = TrustGraph()
        a, b = Node(AGENT, "a"), Node(AGENT, "b")
        src, sink = Node(FILE, "bad"), Node(NETWORK, "out")
        g.add_edge(src, a, "taints")
        g.add_edge(a, b, "calls")
        g.add_edge(b, a, "calls")             # cycle
        g.add_edge(b, sink, "egresses")
        g.mark_untrusted(src)
        g.mark_sink(sink)
        findings = g.taint_paths()             # must terminate, not loop
        assert any(f.rule == "TG-001" for f in findings)

    def test_privilege_bridge_found(self):
        g = TrustGraph()
        user = Node(USER, "analyst")
        agent = Node(AGENT, "shared-bot")
        privileged = Node(TOOL, "filesystem.delete")
        g.add_edge(user, agent, "operates")
        g.add_edge(agent, privileged, "invokes")
        # analyst's role grants only read; delete is reachable via the agent
        findings = g.privilege_bridges({"analyst": {"filesystem.read"}})
        assert any(f.rule == "TG-002" and "filesystem.delete" in f.detail
                   for f in findings)

    def test_no_bridge_when_role_grants_the_tool(self):
        g = TrustGraph()
        user = Node(USER, "admin")
        agent = Node(AGENT, "bot")
        tool = Node(TOOL, "filesystem.delete")
        g.add_edge(user, agent, "operates")
        g.add_edge(agent, tool, "invokes")
        assert g.privilege_bridges({"admin": {"filesystem.delete"}}) == []

    def test_blast_radius_from_compromised_node(self):
        g = TrustGraph()
        agent = Node(AGENT, "a1")
        f1, f2 = Node(FILE, "a.txt"), Node(FILE, "b.txt")
        net = Node(NETWORK, "x.example")
        g.add_edge(agent, f1, "reads")
        g.add_edge(agent, f2, "writes")
        g.add_edge(agent, net, "egresses")
        radius = g.blast_radius(agent)
        assert str(f1) in radius and str(net) in radius and len(radius) == 3


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------
def _strict_engine(tmp_path):
    p = tmp_path / "candidate.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp_path}'\n"
        "tools:\n"
        "  read_file: {tier: auto, path_args: [path]}\n"
        "  write_file: {tier: deny}\n")     # candidate DENIES writes
    return PolicyEngine(str(p))


def _lenient_records():
    # Simulated recorded corpus: reads allowed, a write that was allowed.
    return [
        {"tool": "read_file", "decision": "ALLOW",
         "detail": json.dumps({"args": {"path": "notes.txt"}})},
        {"tool": "read_file", "decision": "ALLOW",
         "detail": json.dumps({"args": {"path": "data.txt"}})},
        {"tool": "write_file", "decision": "ALLOW",
         "detail": json.dumps({"args": {"path": "out.txt"}})},
    ]


class TestReplayEngine:
    def test_stricter_candidate_flags_would_break(self, tmp_path):
        report = simulate(_strict_engine(tmp_path), _lenient_records())
        assert report.replayable == 3
        assert report.would_break_count == 1          # the write
        assert any(d.tool == "write_file" and d.direction == "stricter"
                   for d in report.newly_stricter)

    def test_unchanged_calls_counted(self, tmp_path):
        report = simulate(_strict_engine(tmp_path), _lenient_records())
        assert report.unchanged == 2                  # the two reads

    def test_lifecycle_events_skipped_not_guessed(self, tmp_path):
        records = _lenient_records() + [
            {"tool": None, "decision": "SANDBOX_PROVISIONED",
             "detail": json.dumps({"isolation": "docker"})}]
        report = simulate(_strict_engine(tmp_path), records)
        assert report.skipped == 1
        assert report.total == 4 and report.replayable == 3

    def test_unreconstructable_record_skipped(self, tmp_path):
        records = [{"tool": "read_file", "decision": "ALLOW",
                    "detail": json.dumps({"note": "no args captured"})}]
        report = simulate(_strict_engine(tmp_path), records)
        assert report.skipped == 1 and report.replayable == 0

    def test_replay_is_side_effect_free(self, tmp_path):
        # Replaying must not write to any audit chain: the candidate engine
        # has no AuditLog attached, and decide() must not require one.
        eng = _strict_engine(tmp_path)
        before = simulate(eng, _lenient_records())
        after = simulate(eng, _lenient_records())
        assert before.replayable == after.replayable == 3   # deterministic, stateless

    def test_summary_is_honest_about_skips(self, tmp_path):
        records = _lenient_records() + [
            {"tool": None, "decision": "OPEN", "detail": "{}"}]
        report = simulate(_strict_engine(tmp_path), records)
        assert "not re-decidable" in report.summary()


# ---------------------------------------------------------------------------
# Adaptive policy — context floors, tighten-only
# ---------------------------------------------------------------------------
class TestAdaptivePolicy:
    def test_context_floor_tightens(self):
        ap = AdaptivePolicy([ContextRule("quarantined", "ESCALATE")])
        verdict, rule = ap.apply("ALLOW", {"quarantined"})
        assert verdict == "ESCALATE" and rule == "ADAPT-001"

    def test_context_never_loosens(self):
        # A DENY must survive any context — the floor can only raise.
        ap = AdaptivePolicy([ContextRule("quarantined", "ESCALATE")])
        verdict, rule = ap.apply("DENY", {"quarantined"})
        assert verdict == "DENY" and rule is None

    def test_inactive_context_is_noop(self):
        ap = AdaptivePolicy([ContextRule("quarantined", "DENY")])
        assert ap.apply("ALLOW", set()) == ("ALLOW", None)

    def test_strictest_matching_rule_wins(self):
        ap = AdaptivePolicy([ContextRule("off_goal", "ESCALATE"),
                             ContextRule("quarantined", "DENY")])
        verdict, _ = ap.apply("ALLOW", {"off_goal", "quarantined"})
        assert verdict == "DENY"

    def test_bad_floor_refused_at_construction(self):
        with pytest.raises(ValueError):
            ContextRule("x", "MAYBE")

    def test_from_policy_builds_rules(self):
        ap = AdaptivePolicy.from_policy(
            {"context_rules": [{"when": "off_goal", "floor": "ESCALATE"}]})
        assert ap.apply("ALLOW", {"off_goal"})[0] == "ESCALATE"


# ---------------------------------------------------------------------------
# Quarantine — sticky, human-clear only
# ---------------------------------------------------------------------------
class TestQuarantine:
    def test_quarantine_sets_a_floor(self):
        q = Quarantine()
        q.quarantine("session:abc", "behavioral anomaly")
        verdict, rule = q.floor_for("session:abc")
        assert verdict == "ESCALATE" and rule == "QUAR-001"

    def test_uninvolved_principal_has_no_floor(self):
        q = Quarantine()
        q.quarantine("session:abc", "x")
        assert q.floor_for("session:other") == ("ALLOW", None)

    def test_clear_requires_a_named_human(self):
        q = Quarantine()
        q.quarantine("tool:http_get", "suspicious egress")
        with pytest.raises(ValueError):
            q.clear("tool:http_get", cleared_by="")
        assert q.is_quarantined("tool:http_get")        # still held after bad clear

    def test_human_clear_releases(self):
        q = Quarantine()
        q.quarantine("tool:http_get", "x")
        assert q.clear("tool:http_get", cleared_by="analyst@corp")
        assert not q.is_quarantined("tool:http_get")

    def test_does_not_self_expire(self):
        # There is no tick/expire method at all — statelessness over time IS
        # the property. Assert the surface has no expiry hook.
        q = Quarantine()
        assert not any(hasattr(q, name)
                       for name in ("expire", "tick", "sweep", "ttl"))

    def test_strictest_floor_across_principals(self):
        q = Quarantine()
        q.quarantine("session:abc", "x", floor="ESCALATE")
        q.quarantine("tool:exec", "y", floor="DENY")
        assert q.floor_for("session:abc", "tool:exec")[0] == "DENY"


# ---------------------------------------------------------------------------
# Intent verification
# ---------------------------------------------------------------------------
class TestIntentVerifier:
    def test_off_goal_sensitive_action_flagged(self):
        iv = IntentVerifier()
        off, why = iv.check("summarize the quarterly report", "filesystem.delete")
        assert off and "off-goal" in why

    def test_on_goal_action_passes(self):
        iv = IntentVerifier()
        off, _ = iv.check("summarize the quarterly report", "filesystem.read")
        assert not off

    def test_no_goal_means_nothing_to_verify(self):
        iv = IntentVerifier()
        off, _ = iv.check(None, "filesystem.delete")
        assert not off

    def test_goal_with_no_known_verb_is_permissive(self):
        # Conservative by design: an unrecognized goal does not manufacture
        # off-goal alarms that would train humans to ignore the signal.
        iv = IntentVerifier()
        off, _ = iv.check("frobnicate the widgets", "filesystem.delete")
        assert not off

    def test_send_goal_permits_send_action(self):
        iv = IntentVerifier()
        off, _ = iv.check("send the summary to the team", "email.send")
        assert not off


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------
class TestPolicyValidation:
    def _load(self, tmp_path, block):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            f"{block}"
            "tools:\n  read_file: {tier: auto}\n")
        return PolicyEngine(str(p))

    def test_bad_context_floor_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "adaptive:\n  context_rules:\n"
                       "    - {when: quarantined, floor: PERHAPS}\n")

    def test_context_rule_missing_fields_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "adaptive:\n  context_rules:\n    - {when: quarantined}\n")

    def test_negative_warmup_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "adaptive:\n  behavior: {warmup_calls: -5}\n")

    def test_valid_adaptive_block_loads(self, tmp_path):
        eng = self._load(tmp_path,
                         "adaptive:\n  enabled: true\n"
                         "  behavior: {warmup_calls: 15}\n"
                         "  context_rules:\n"
                         "    - {when: off_goal, floor: ESCALATE}\n")
        assert eng.policy["adaptive"]["behavior"]["warmup_calls"] == 15

    def test_absent_block_changes_nothing(self, tmp_path):
        eng = self._load(tmp_path, "")
        assert not eng.policy.get("adaptive")


# ---------------------------------------------------------------------------
# Audit corpus integration — replay reads real recorded decisions
# ---------------------------------------------------------------------------
class TestAuditReplayIntegration:
    def test_replay_consumes_real_audit_records(self, tmp_path):
        from proxy.audit.log import AuditLog
        audit = AuditLog(str(tmp_path / "audit.db"))
        # Record two decisions the way monitor mode would, with args in detail.
        audit.record("read_file", "ALLOW", "clean read",
                     {"args": {"path": "notes.txt"}})
        audit.record("write_file", "ALLOW", "monitor-mode observed",
                     {"args": {"path": "out.txt"}})

        records = audit.records()
        assert len(records) == 2

        report = simulate(_strict_engine(tmp_path), records)
        assert report.would_break_count == 1          # the write, under strict policy
        audit.close()

    def test_records_reader_is_read_only(self, tmp_path):
        from proxy.audit.log import AuditLog
        audit = AuditLog(str(tmp_path / "audit.db"))
        audit.record("read_file", "ALLOW", "x", {"args": {"path": "a"}})
        audit.records()
        audit.records()
        assert audit.verify_chain()                   # reading never mutated the chain
        audit.close()
