"""
tests/test_v4_identity_trust.py

v4 — Identity & Trust. Capability tokens (mint, verify, forge, replay,
expire, scope), agent RBAC (user roles intersected with agent scope),
the full approval gate (per-capability policies, history on the audit
chain, timeout and escalation), secure sessions (workspace, grants,
canaries, destruction), and memory integrity (sign, chain, version,
head-pin, tamper and rollback detection).

Clocks are injected everywhere time matters, keys never leave their
issuers, and every "attack" is a synthetic manipulation of bytes on disk
or tokens in memory — nothing here touches a network or a real credential.
"""

import json
import time

import pytest

from warden.core.request import Request
from warden.core.decision import Verdict
from warden.policy.engine import PolicyEngine, PolicyValidationError
from warden.audit.log import AuditLog
from warden.runtime.mediator import Mediator
from warden.runtime.approval import (
    ApprovalGate, ApprovalHistory, ApprovalPolicies, ApprovalPolicyError,
    ApprovalResult, EscalatingApprovalGate)

from warden.identity.capabilities import (
    CapabilityIssuer, CapabilitySet, capability_matches, target_matches)
from warden.identity.rbac import Rbac
from warden.identity.sessions import SecureSession, SessionManager
from warden.identity.memguard import MemoryVault, MemoryIntegrityError


# ---------------------------------------------------------------------------
# Capability matching semantics
# ---------------------------------------------------------------------------
class TestCapabilityMatching:
    def test_exact_match(self):
        assert capability_matches("filesystem.read", "filesystem.read")
        assert not capability_matches("filesystem.read", "filesystem.write")

    def test_family_wildcard_widens_only_downward(self):
        assert capability_matches("filesystem.*", "filesystem.delete")
        # A specific grant is never stretched into its family...
        assert not capability_matches("filesystem.read", "filesystem.*")
        # ...and the family wildcard does not cover the bare family name.
        assert not capability_matches("filesystem.*", "filesystem")

    def test_target_globs(self):
        assert target_matches("*", "/anything/at/all")
        assert target_matches("/ws/data/*", "/ws/data/file.txt")
        assert not target_matches("/ws/data/*", "/ws/secrets/key")


# ---------------------------------------------------------------------------
# Capability tokens — mint, verify, and every way to fail
# ---------------------------------------------------------------------------
class TestCapabilityTokens:
    def setup_method(self):
        self.t = [1000.0]
        self.issuer = CapabilityIssuer("S-test", clock=lambda: self.t[0])

    def test_mint_verify_roundtrip(self):
        tok = self.issuer.mint("filesystem.read", "/ws/*")
        r = self.issuer.verify(tok, "filesystem.read", "/ws/notes.txt")
        assert r.ok and r.capability == "filesystem.read"

    def test_wrong_capability_refused(self):
        tok = self.issuer.mint("filesystem.read", "*")
        r = self.issuer.verify(tok, "filesystem.write", "/ws/x")
        assert not r.ok and "requires" in r.reason

    def test_out_of_scope_target_refused(self):
        tok = self.issuer.mint("filesystem.read", "/ws/data/*")
        r = self.issuer.verify(tok, "filesystem.read", "/ws/secrets/key")
        assert not r.ok and "outside the grant's scope" in r.reason

    def test_forged_signature_refused(self):
        tok = self.issuer.mint("filesystem.read", "*")
        head, body, sig = tok.split(".")
        forged = f"{head}.{body}.{'0' * len(sig)}"
        r = self.issuer.verify(forged, "filesystem.read", "/x")
        assert not r.ok and "signature" in r.reason

    def test_tampered_payload_refused(self):
        # Flip the payload to claim a wider capability; the signature is
        # over the original bytes, so tampering is a signature failure.
        import base64
        tok = self.issuer.mint("filesystem.read", "/ws/*")
        head, body, sig = tok.split(".")
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        payload["cap"] = "filesystem.*"
        payload["tgt"] = "*"
        evil = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        r = self.issuer.verify(f"{head}.{evil}.{sig}", "filesystem.delete", "/etc/passwd")
        assert not r.ok and "signature" in r.reason

    def test_foreign_session_token_refused(self):
        other = CapabilityIssuer("S-other", clock=lambda: self.t[0])
        tok = other.mint("filesystem.read", "*")
        r = self.issuer.verify(tok, "filesystem.read", "/x")
        assert not r.ok   # foreign key -> signature failure

    def test_expiry_with_injected_clock(self):
        tok = self.issuer.mint("filesystem.read", "*", ttl_seconds=60)
        self.t[0] = 1061.0
        r = self.issuer.verify(tok, "filesystem.read", "/x")
        assert not r.ok and "expired" in r.reason

    def test_single_use_replay_refused(self):
        tok = self.issuer.mint("filesystem.read", "*", single_use=True)
        assert self.issuer.verify(tok, "filesystem.read", "/x").ok
        r = self.issuer.verify(tok, "filesystem.read", "/x")
        assert not r.ok and "replayed" in r.reason

    def test_reusable_grant_survives_reuse(self):
        tok = self.issuer.mint("filesystem.read", "*", single_use=False)
        assert self.issuer.verify(tok, "filesystem.read", "/a").ok
        assert self.issuer.verify(tok, "filesystem.read", "/b").ok

    def test_malformed_and_wrong_version_refused(self):
        assert not self.issuer.verify("garbage", "x", "y").ok
        assert not self.issuer.verify("WCAP9.aaaa.bbbb", "x", "y").ok
        assert not self.issuer.verify("", "x", "y").ok

    def test_revocation_kills_everything(self):
        tok = self.issuer.mint("filesystem.read", "*", single_use=False)
        self.issuer.revoke_all()
        r = self.issuer.verify(tok, "filesystem.read", "/x")
        assert not r.ok and "revoked" in r.reason
        with pytest.raises(RuntimeError):
            self.issuer.mint("filesystem.read", "*")

    def test_capability_set_covers(self):
        caps = CapabilitySet(self.issuer)
        caps.grant("filesystem.read", "/ws/*")
        assert caps.covers("filesystem.read", "/ws/a.txt").ok
        assert not caps.covers("filesystem.write", "/ws/a.txt").ok
        assert not caps.covers("filesystem.read", "/etc/passwd").ok


# ---------------------------------------------------------------------------
# RBAC — user roles vs. agent scope
# ---------------------------------------------------------------------------
RBAC_CFG = {
    "enabled": True,
    "default_role": None,
    "roles": {
        "analyst": {"tools": ["read_file", "http_get"],
                    "capabilities": [
                        {"capability": "filesystem.read", "target": "*"}]},
        "operator": {"tools": ["*"]},
        "prefixed": {"tools": ["fs_*"]},
    },
    "users": {"meca": "operator", "agent": "analyst", "batch": "prefixed"},
}


class TestRbac:
    def test_role_permits(self):
        r = Rbac(RBAC_CFG)
        assert r.check("agent", "read_file").permitted
        assert r.check("meca", "anything_at_all").permitted

    def test_role_denies_unlisted_tool(self):
        v = Rbac(RBAC_CFG).check("agent", "delete_file")
        assert not v.permitted and v.rule == "RBAC-001"

    def test_unknown_user_denied_by_default(self):
        v = Rbac(RBAC_CFG).check("stranger", "read_file")
        assert not v.permitted and v.rule == "RBAC-001" and "no role" in v.reason

    def test_default_role_opts_into_anonymous_access(self):
        cfg = dict(RBAC_CFG, default_role="analyst")
        assert Rbac(cfg).check("stranger", "read_file").permitted

    def test_user_mapped_to_undeclared_role_denied(self):
        cfg = dict(RBAC_CFG, users={"ghost": "no_such_role"})
        v = Rbac(cfg).check("ghost", "read_file")
        assert not v.permitted and v.rule == "RBAC-001"

    def test_prefix_wildcard_tools(self):
        r = Rbac(RBAC_CFG)
        assert r.check("batch", "fs_list").permitted
        assert not r.check("batch", "http_get").permitted

    def test_agent_scope_narrows_never_widens(self):
        cfg = dict(RBAC_CFG, agent_scope=["read_file"])
        r = Rbac(cfg)
        # Operator may run anything — but THIS deployment only runs read_file.
        v = r.check("meca", "http_get")
        assert not v.permitted and v.rule == "RBAC-002"
        assert r.check("meca", "read_file").permitted
        # And scope grants nothing the role didn't: analyst still can't delete.
        cfg2 = dict(RBAC_CFG, agent_scope=["delete_file", "read_file"])
        v2 = Rbac(cfg2).check("agent", "delete_file")
        assert not v2.permitted and v2.rule == "RBAC-001"

    def test_empty_agent_scope_means_no_tools(self):
        cfg = dict(RBAC_CFG, agent_scope=[])
        v = Rbac(cfg).check("meca", "read_file")
        assert not v.permitted and v.rule == "RBAC-002"

    def test_disabled_rbac_changes_nothing(self):
        r = Rbac({"enabled": False})
        assert r.check("anyone", "anything").permitted

    def test_role_capabilities_extraction(self):
        grants = Rbac(RBAC_CFG).role_capabilities("agent")
        assert grants == [{"capability": "filesystem.read", "target": "*"}]
        assert Rbac(RBAC_CFG).role_capabilities("stranger") == []


# ---------------------------------------------------------------------------
# Approval policies, history, and the escalation chain
# ---------------------------------------------------------------------------
class TestApprovalPolicies:
    def test_always_fires(self):
        pol = ApprovalPolicies({"filesystem.delete": "always"})
        assert pol.requirement(["filesystem.delete"], 0).required

    def test_risk_threshold(self):
        pol = ApprovalPolicies({"network.egress": "risk>=50"})
        assert not pol.requirement(["network.egress"], 49).required
        assert pol.requirement(["network.egress"], 50).required

    def test_never_is_inert(self):
        pol = ApprovalPolicies({"read_file": "never"})
        assert not pol.requirement(["read_file"], 100).required

    def test_unmentioned_names_add_nothing(self):
        pol = ApprovalPolicies({"filesystem.delete": "always"})
        assert not pol.requirement(["filesystem.read", "read_file"], 100).required

    def test_bad_rule_rejected_at_parse(self):
        with pytest.raises(ApprovalPolicyError):
            ApprovalPolicies({"x": "sometimes"})
        with pytest.raises(ApprovalPolicyError):
            ApprovalPolicies({"x": "risk>=lots"})


class TestApprovalHistoryAndChain:
    def test_history_reads_the_audit_chain(self, tmp_path):
        log = AuditLog(str(tmp_path / "a.db"))
        log.record("write_file", "APPROVED", "human said yes", {"rule": "TOOL-003"})
        log.record("write_file", "REJECTED", "human said no", {"rule": "TOOL-003"})
        log.record("write_file", "REJECTED", "human said no", {"rule": "TOOL-003"})
        log.record("other_tool", "APPROVED", "yes", {"rule": "TOOL-003"})
        h = ApprovalHistory(log)
        counts = h.summary(tool="write_file")
        assert counts == {"APPROVED": 1, "REJECTED": 2}
        line = h.prompt_line("write_file")
        assert "1 approved" in line and "2 rejected" in line
        assert "no prior" in h.prompt_line("never_seen")
        recent = h.recent(tool="write_file", limit=2)
        assert len(recent) == 2 and all(r["tool"] == "write_file" for r in recent)
        log.close()

    def test_gate_prompt_includes_history(self, tmp_path):
        log = AuditLog(str(tmp_path / "a.db"))
        log.record("write_file", "REJECTED", "no", {"rule": "TOOL-003"})
        seen = {}
        gate = ApprovalGate(asker=lambda p: seen.setdefault("prompt", p) and "n" or "n",
                            history=ApprovalHistory(log))

        class FakeDecision:
            action = "write_file"
            def explain(self):
                return "rule TOOL-003, risk 40"
        r = gate.request_approval(FakeDecision())
        assert not r.approved
        assert "History for 'write_file'" in seen["prompt"]
        log.close()

    def test_history_failure_never_blocks_the_ask(self):
        class BrokenHistory:
            def prompt_line(self, _tool):
                raise RuntimeError("db gone")
        gate = ApprovalGate(asker=lambda _p: "y", history=BrokenHistory())

        class FakeDecision:
            action = "x"
            def explain(self):
                return "d"
        assert gate.request_approval(FakeDecision()).approved


class TestEscalationChain:
    class _D:
        action = "write_file"
        def explain(self):
            return "decision"

    def _silent(self):
        return ApprovalGate(asker=lambda _p: None)   # timeout -> non-answer

    def test_absent_first_approver_escalates_to_second(self):
        chain = EscalatingApprovalGate([self._silent(),
                                        ApprovalGate(asker=lambda _p: "y")])
        r = chain.request_approval(self._D())
        assert r.approved and "escalation level 2" in r.detail

    def test_explicit_no_stops_the_chain(self):
        asked = {"second": False}
        def second_asker(_p):
            asked["second"] = True
            return "y"
        chain = EscalatingApprovalGate([ApprovalGate(asker=lambda _p: "n"),
                                        ApprovalGate(asker=second_asker)])
        r = chain.request_approval(self._D())
        assert not r.approved
        assert not asked["second"], "a human 'no' must never be shopped to the next approver"

    def test_exhausted_chain_fails_closed(self):
        chain = EscalatingApprovalGate([self._silent(), self._silent()])
        r = chain.request_approval(self._D())
        assert not r.approved and "exhausted" in r.detail

    def test_empty_chain_rejected(self):
        with pytest.raises(ValueError):
            EscalatingApprovalGate([])


# ---------------------------------------------------------------------------
# Secure sessions
# ---------------------------------------------------------------------------
class TestSessions:
    def test_open_provisions_workspace_grants_and_canaries(self, tmp_path):
        from warden.network.canary import CanaryVault
        canary = CanaryVault(str(tmp_path / "canaries.json"))
        mgr = SessionManager(str(tmp_path / "sessions"), rbac=Rbac(RBAC_CFG),
                             canary=canary)
        s = mgr.open("agent")
        assert s.workspace.exists()
        assert len(s.canary_paths) == 3
        assert s.covers("filesystem.read", "/anything").ok
        assert not s.covers("filesystem.delete", "/anything").ok

    def test_session_ids_unique_and_workspaces_isolated(self, tmp_path):
        mgr = SessionManager(str(tmp_path / "sessions"))
        a, b = mgr.open("u1"), mgr.open("u2")
        assert a.session_id != b.session_id
        assert a.workspace != b.workspace
        (a.workspace / "private.txt").write_text("session A data")
        assert not (b.workspace / "private.txt").exists()

    def test_destroy_wipes_revokes_and_is_idempotent(self, tmp_path):
        mgr = SessionManager(str(tmp_path / "sessions"), rbac=Rbac(RBAC_CFG))
        s = mgr.open("agent")
        (s.workspace / "leftover.txt").write_text("should not survive")
        tok = s.grant("filesystem.write", "/tmp/*", single_use=False)
        summary = mgr.close(s)
        assert summary["workspace_wiped"] and not s.workspace.exists()
        assert not s.covers("filesystem.read", "/x").ok       # closed session
        assert not s.issuer.verify(tok, "filesystem.write", "/tmp/f").ok
        with pytest.raises(RuntimeError):
            s.grant("filesystem.read")
        again = mgr.close(s)
        assert again.get("already_closed")

    def test_open_and_close_land_on_the_audit_chain(self, tmp_path):
        log = AuditLog(str(tmp_path / "a.db"))
        mgr = SessionManager(str(tmp_path / "sessions"), audit=log)
        s = mgr.open("agent")
        mgr.close(s)
        rows = list(log._conn.execute(
            "SELECT decision, parent_event_id FROM audit ORDER BY seq"))
        assert rows[0][0] == "SESSION_OPEN"
        assert rows[1][0] == "SESSION_CLOSE"
        assert rows[1][1] is not None    # close is parent-linked to open
        assert log.verify_chain()
        log.close()


# ---------------------------------------------------------------------------
# Memory integrity
# ---------------------------------------------------------------------------
class TestMemoryVault:
    def test_put_get_and_versioning(self, tmp_path):
        v = MemoryVault(str(tmp_path / "mem.json"))
        assert v.put("project", "warden is at v3") == 1
        assert v.put("project", "warden is at v4") == 2
        assert v.get("project") == "warden is at v4"
        assert v.get("project", version=1) == "warden is at v3"
        assert [ver for ver, _ts in v.history("project")] == [1, 2]
        assert v.get("never_written") is None

    def test_reopen_verifies_clean_store(self, tmp_path):
        path = str(tmp_path / "mem.json")
        MemoryVault(path).put("k", "v")
        assert MemoryVault(path).get("k") == "v"

    def test_content_tamper_detected_mem001(self, tmp_path):
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("fact", "the deploy key is rotated monthly")
        records = json.loads(path.read_text())
        records[0]["content"] = "the deploy key never rotates"   # poison it
        path.write_text(json.dumps(records))
        violations = v.verify()
        assert any(x.rule == "MEM-001" for x in violations)
        with pytest.raises(MemoryIntegrityError):
            v.get("fact")

    def test_chain_break_on_deletion_detected(self, tmp_path):
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("a", "1"); v.put("b", "2"); v.put("c", "3")
        records = json.loads(path.read_text())
        del records[1]                                   # delete from the middle
        path.write_text(json.dumps(records))
        assert any(x.rule in ("MEM-001", "MEM-002") for x in v.verify())

    def test_rollback_detected_mem002(self, tmp_path):
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("k", "old state")
        snapshot = path.read_text()                      # attacker snapshots here
        v.put("k", "new state the attacker wants gone")
        path.write_text(snapshot)                        # roll the file back
        violations = v.verify()
        assert any(x.rule == "MEM-002" and "rollback" in x.detail for x in violations)

    def test_head_deletion_is_a_rollback_signature(self, tmp_path):
        # Regression for the head-deletion bypass found in review: truncating
        # the store AND deleting the head produced an internally-valid chain
        # with no rollback witness — silence, where there must be an alarm.
        # Deleting the witness does not acquit the defendant.
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("k", "old state")
        snapshot = path.read_text()
        v.put("k", "state the attacker wants gone")
        path.write_text(snapshot)                        # roll back...
        path.with_suffix(path.suffix + ".head").unlink() # ...and burn the witness
        violations = v.verify()
        assert any(x.rule == "MEM-002" and "missing" in x.detail for x in violations)

    def test_forged_head_fails_closed(self, tmp_path):
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("k", "v")
        head_path = path.with_suffix(path.suffix + ".head")
        head = json.loads(head_path.read_text())
        head["count"] = 0                                # try to bless a wipe
        head_path.write_text(json.dumps(head))
        with pytest.raises(MemoryIntegrityError):
            v.verify()

    def test_unparseable_store_fails_closed(self, tmp_path):
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path))
        v.put("k", "v")
        path.write_text("{{{ not json")
        with pytest.raises(MemoryIntegrityError):
            v.get("k")

    def test_encryption_roundtrip_or_clean_skip(self, tmp_path):
        pytest.importorskip("cryptography")
        path = tmp_path / "mem.json"
        v = MemoryVault(str(path), encrypt=True)
        v.put("secretish", "content at rest must not be plaintext")
        on_disk = path.read_text()
        assert "content at rest" not in on_disk
        assert v.get("secretish") == "content at rest must not be plaintext"

    def test_encrypt_without_library_fails_loud(self, tmp_path, monkeypatch):
        import builtins
        real_import = builtins.__import__
        def no_crypto(name, *a, **k):
            if name.startswith("cryptography"):
                raise ImportError("not installed")
            return real_import(name, *a, **k)
        monkeypatch.setattr(builtins, "__import__", no_crypto)
        with pytest.raises(MemoryIntegrityError):
            MemoryVault(str(tmp_path / "mem.json"), encrypt=True)


# ---------------------------------------------------------------------------
# Engine + mediator integration
# ---------------------------------------------------------------------------
V4_POLICY = """\
version: 1
workspace_root: '{root}'
mode: enforce
identity:
  rbac:
    enabled: true
    roles:
      analyst:
        tools: [read_file, delete_file]
        capabilities:
          - {{capability: filesystem.read, target: "*"}}
      operator:
        tools: ["*"]
        capabilities:
          - {{capability: "filesystem.*", target: "*"}}
    users:
      agent: analyst
      meca: operator
  capabilities:
    enabled: true
  approval:
    history: true
    policies:
      filesystem.delete: always
tools:
  read_file: {{tier: auto, path_args: [path], capability: filesystem.read}}
  delete_file: {{tier: auto, path_args: [path], capability: filesystem.delete}}
  http_get: {{tier: auto, url_args: [url]}}
"""


@pytest.fixture
def v4(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(V4_POLICY.format(root=str(tmp_path).replace("\\", "/")))
    engine = PolicyEngine(str(p))
    audit = AuditLog(str(tmp_path / "audit.db"))
    from warden.runtime.approval import ApprovalGate as AG
    m = Mediator(engine, audit, approval=AG(asker=lambda _p: "y"))
    yield engine, m, tmp_path
    audit.close()


class TestV4Integration:
    def test_rbac_denies_through_engine(self, v4):
        engine, _m, _ = v4
        d = engine.decide(Request.normalize("http_get",
                                            {"url": "https://x.example"},
                                            user="agent"))
        assert d.verdict == Verdict.DENY and d.rule == "RBAC-001"

    def test_unknown_user_denied(self, v4):
        engine, _m, _ = v4
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"},
                                            user="stranger"))
        assert d.verdict == Verdict.DENY and d.rule == "RBAC-001"

    def test_capability_required_without_session_denies(self, v4):
        engine, _m, _ = v4
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"},
                                            user="agent"))
        assert d.verdict == Verdict.DENY and d.rule == "CAP-001"

    def test_session_grant_allows_and_close_revokes(self, v4):
        _engine, m, _ = v4
        s = m.open_session("agent")
        out = m.mediate_call("read_file", {"path": "notes.txt"}, session=s)
        assert out.execute, out.decision.reason
        m.close_session(s)
        out2 = m.mediate_call("read_file", {"path": "notes.txt"}, session=s)
        assert not out2.execute and out2.decision.rule == "FAIL-001"

    def test_role_without_capability_denies_cap001(self, v4):
        # analyst's role permits the delete TOOL but grants no
        # filesystem.delete capability — tiers and grants are different
        # questions, and both must say yes.
        _engine, m, _ = v4
        s = m.open_session("agent")
        out = m.mediate_call("delete_file", {"path": "notes.txt"}, session=s)
        assert not out.execute and out.decision.rule == "CAP-001"
        m.close_session(s)

    def test_approval_policy_escalates_and_lands_on_chain(self, v4):
        _engine, m, tmp = v4
        s = m.open_session("meca")     # operator holds filesystem.*
        out = m.mediate_call("delete_file", {"path": "old.txt"}, session=s)
        # policy filesystem.delete: always -> APR-001 escalate -> asker says y
        assert out.decision.rule == "APR-001"
        assert out.execute
        rows = [r[0] for r in m.audit._conn.execute(
            "SELECT decision FROM audit ORDER BY seq")]
        assert "APPROVED" in rows and m.audit.verify_chain()
        m.close_session(s)

    def test_session_canaries_armed_from_first_call(self, v4):
        # The v3 tripwire and v4 sessions meet: a marker planted at session
        # open, moving through outbound args, is a CAN-001 confirmed exfil.
        _engine, m, _ = v4
        m.canary = __import__("warden.network.canary", fromlist=["CanaryVault"]).CanaryVault()
        s = m.open_session("meca")
        token = next(iter(m.canary._tokens))
        out = m.mediate_call("read_file", {"path": f"notes-{token}.txt"}, session=s)
        assert not out.execute and out.decision.rule == "CAN-001"
        m.close_session(s)

    def test_policy_without_identity_block_unchanged(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools:\n  read_file: {tier: auto, path_args: [path]}\n")
        engine = PolicyEngine(str(p))
        d = engine.decide(Request.normalize("read_file", {"path": "a.txt"},
                                            user="whoever"))
        assert d.verdict == Verdict.ALLOW


# ---------------------------------------------------------------------------
# Policy validation for the identity block
# ---------------------------------------------------------------------------
class TestIdentityPolicyValidation:
    def _load(self, tmp_path, identity_block):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            f"{identity_block}"
            "tools:\n  read_file: {tier: auto}\n")
        return PolicyEngine(str(p))

    def test_user_to_undeclared_role_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "identity:\n  rbac:\n    enabled: true\n"
                       "    roles: {analyst: {tools: [read_file]}}\n"
                       "    users: {agent: ghost_role}\n")

    def test_undeclared_default_role_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "identity:\n  rbac:\n    enabled: true\n"
                       "    default_role: nope\n"
                       "    roles: {analyst: {tools: [read_file]}}\n")

    def test_bad_approval_rule_rejected_at_load(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "identity:\n  approval:\n    policies: {x: sometimes}\n")

    def test_bad_role_tools_type_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "identity:\n  rbac:\n"
                       "    roles: {analyst: {tools: 'read_file'}}\n")

    def test_valid_identity_block_loads(self, tmp_path):
        eng = self._load(
            tmp_path,
            "identity:\n  rbac:\n    enabled: true\n"
            "    roles: {analyst: {tools: [read_file]}}\n"
            "    users: {agent: analyst}\n"
            "  capabilities: {enabled: true}\n"
            "  approval:\n    policies: {'filesystem.delete': always}\n")
        assert eng.rbac.enabled and eng.capabilities_enabled
