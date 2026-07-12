"""
tests/test_v7_platform.py  (v7 — Warden Platform)

What v7 must prove:

  PACKAGING     the distribution is installable, the version is consistent
                everywhere it appears, and the dependency pins are real pins.
  ADAPTERS      every framework adapter routes through the one gate; DENY
                means the tool never runs; ESCALATE goes to a human; every
                call is audited; unrecognized tool shapes are refused loudly.
  BUNDLES       pack -> verify -> install round-trips; any tampered byte
                fails verification; unsigned installs are refused by default;
                traversal member names are rejected; missing crypto fails
                loud, never silently unsigned.
  DASHBOARD     localhost-bound, token-authenticated (401 without, 200 with),
                read-only over live state; candidate validate/replay work and
                never touch the live policy.
"""

from __future__ import annotations

import json
import http.client
import zipfile
from pathlib import Path

import pytest

import warden
from warden.adapters import (
    AdapterShapeError, WardenDenied, WardenGate,
    guard_autogen_map, guard_crewai_tools,
    guard_langchain_tools, guard_openai_tools,
)
from warden.audit.log import AuditLog
from warden.platform import bundle as B
from warden.platform.dashboard import DashboardServer
from warden.runtime.approval import ApprovalGate

REPO = Path(__file__).resolve().parent.parent

try:
    import cryptography                                    # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

POLICY = """\
version: 1
mode: enforce
workspace_root: '{ws}'
tools:
  read_file: {{tier: auto, path_args: [path]}}
  send_email: {{tier: escalate}}
audit: {{enabled: true, path: '{audit}'}}
"""


@pytest.fixture
def gate(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    policy = tmp_path / "policy.yaml"
    audit = tmp_path / "audit.db"
    policy.write_text(POLICY.format(ws=ws, audit=audit))
    g = WardenGate(str(policy), str(audit),
                   approval=ApprovalGate(asker=lambda _p: "no"))
    yield g
    g.close()


def _decisions(audit_path: str) -> list[tuple[str, str]]:
    log = AuditLog(audit_path)
    try:
        return [(r["tool"], r["decision"]) for r in log.records()]
    finally:
        log.close()


# --------------------------------------------------------------------------- #
# packaging & version consistency
# --------------------------------------------------------------------------- #

class TestPackaging:
    def test_version_consistent_everywhere(self):
        """__version__, pyproject, CHANGELOG top entry, and the VS Code
        extension all state the same version. One number, no drift."""
        v = warden.__version__
        pyproject = (REPO / "pyproject.toml").read_text()
        assert f'version = "{v}"' in pyproject
        changelog = (REPO / "CHANGELOG.md").read_text()
        assert f"## [{v}]" in changelog.split("## [", 2)[1][:40] or \
               changelog.split("## [")[1].startswith(v)
        ext = json.loads((REPO / "integrations/vscode/package.json").read_text())
        assert ext["version"] == v

    def test_console_script_points_at_cli_main(self):
        pyproject = (REPO / "pyproject.toml").read_text()
        assert 'warden = "warden.cli:main"' in pyproject

    def test_distribution_name_is_not_the_taken_pypi_name(self):
        """`warden` is taken on PyPI; we ship as warden-security."""
        assert 'name = "warden-security"' in (REPO / "pyproject.toml").read_text()

    def test_lock_file_pins_exactly(self):
        """Every non-comment line in requirements.lock is a hard == pin."""
        for line in (REPO / "requirements.lock").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            assert "==" in line, f"unpinned dependency in lock file: {line}"
        # and the loose runtime dependency set stays deliberately tiny
        pyproject = (REPO / "pyproject.toml").read_text()
        assert 'dependencies = ["pyyaml' in pyproject

    def test_release_workflow_attests_and_hashes(self):
        wf = (REPO / ".github/workflows/release.yml").read_text()
        assert "attest-build-provenance" in wf
        assert "sha256sum" in wf
        assert "id-token: write" in wf

    def test_cli_reports_version(self, capsys):
        from warden.cli import build_parser
        with pytest.raises(SystemExit) as e:
            build_parser().parse_args(["--version"])
        assert e.value.code == 0
        assert warden.__version__ in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# adapters
# --------------------------------------------------------------------------- #

class TestGate:
    def test_allow_executes_and_audits(self, gate):
        ran = {}
        def read_file(path):
            ran["path"] = path
            return "contents"
        out = gate.call("read_file", read_file, {"path": "notes.txt"})
        assert out == "contents" and ran
        assert ("read_file", "ALLOW") in _decisions(str(gate.audit.path)) or \
               any(t == "read_file" for t, _ in _decisions(str(gate.audit.path)))

    def test_deny_never_runs_the_tool(self, gate):
        ran = []
        with pytest.raises(WardenDenied) as e:
            gate.call("delete_everything", lambda **kw: ran.append(1))
        assert not ran, "DENY must mean the callable is never invoked"
        assert e.value.decision.verdict.value == "DENY"
        assert ("delete_everything", "DENY") in _decisions(str(gate.audit.path))

    def test_escalate_refused_raises_and_audits_refusal(self, gate):
        ran = []
        with pytest.raises(WardenDenied):
            gate.call("send_email", lambda **kw: ran.append(1), {"to": "x"})
        assert not ran
        pairs = _decisions(str(gate.audit.path))
        assert ("send_email", "ESCALATE") in pairs
        assert ("send_email", "REFUSED") in pairs

    def test_escalate_approved_runs(self, tmp_path):
        ws = tmp_path / "ws"; ws.mkdir()
        policy = tmp_path / "p.yaml"; audit = tmp_path / "a.db"
        policy.write_text(POLICY.format(ws=ws, audit=audit))
        g = WardenGate(str(policy), str(audit),
                       approval=ApprovalGate(asker=lambda _p: "yes"))
        try:
            assert g.call("send_email", lambda **kw: "sent", {"to": "x"}) == "sent"
            assert ("send_email", "APPROVED") in _decisions(str(audit))
        finally:
            g.close()


class TestFrameworkAdapters:
    def test_autogen_map_guards_every_entry(self, gate):
        ran = []
        guarded = guard_autogen_map(gate, {
            "read_file": lambda path: f"read:{path}",
            "delete_everything": lambda **kw: ran.append(1),
        })
        out = guarded["read_file"](path="notes.txt")
        # the gate applies the engine's path canonicalization before executing:
        # the checked path and the executed path are the same string.
        # (normalize separators so this holds on Windows too)
        assert out.replace("\\", "/").startswith("read:")
        assert out.replace("\\", "/").endswith("/ws/notes.txt")
        with pytest.raises(WardenDenied):
            guarded["delete_everything"]()
        assert not ran

    def test_openai_plain_callable(self, gate):
        def read_file(path):
            return f"read:{path}"
        [g] = guard_openai_tools(gate, [read_file])
        out = g(path="notes.txt")
        assert out.replace("\\", "/").endswith("/ws/notes.txt")

    def test_openai_functiontool_like(self, gate):
        class FunctionTool:                       # SDK duck-type
            name = "read_file"
            def on_invoke_tool(self, ctx, args_json):
                return f"invoked:{args_json}"
        [g] = guard_openai_tools(gate, [FunctionTool()])
        assert g.on_invoke_tool(None, '{"path": "notes.txt"}').startswith("invoked:")

        class DeniedTool:
            name = "delete_everything"
            def on_invoke_tool(self, ctx, args_json):
                raise AssertionError("must never run")
        [d] = guard_openai_tools(gate, [DeniedTool()])
        with pytest.raises(WardenDenied):
            d.on_invoke_tool(None, "{}")

    def test_langchain_tool_like(self, gate):
        class Tool:                               # LangChain duck-type
            name = "read_file"
            def _run(self, path):
                return f"read:{path}"
        [g] = guard_langchain_tools(gate, [Tool()])
        assert g._run(path="notes.txt").endswith("notes.txt")

    def test_crewai_tool_like_denied(self, gate):
        class Tool:
            name = "delete_everything"
            def _run(self, **kw):
                raise AssertionError("must never run")
        [g] = guard_crewai_tools(gate, [Tool()])
        with pytest.raises(WardenDenied):
            g._run()

    def test_unrecognized_shape_is_refused_loudly(self, gate):
        class Mystery:
            name = "thing"                        # a name but nothing callable
        with pytest.raises(AdapterShapeError):
            guard_langchain_tools(gate, [Mystery()])
        with pytest.raises(AdapterShapeError):
            guard_openai_tools(gate, [Mystery()])

    def test_originals_untouched(self, gate):
        class Tool:
            name = "read_file"
            def _run(self, path):
                return "raw"
        t = Tool()
        guard_langchain_tools(gate, [t])
        assert t._run(path="x") == "raw", "guarding must not mutate the original"


# --------------------------------------------------------------------------- #
# bundles (the marketplace format)
# --------------------------------------------------------------------------- #

MINI_POLICY = """\
version: 1
workspace_root: '{ws}'
tools:
  read_file: {{tier: auto, path_args: [path]}}
"""


@pytest.fixture
def policy_dir(tmp_path):
    src = tmp_path / "policies"
    src.mkdir()
    ws = tmp_path / "ws"; ws.mkdir()
    (src / "base.yaml").write_text(MINI_POLICY.format(ws=ws))
    return src


class TestBundles:
    def test_pack_verify_roundtrip_unsigned(self, policy_dir, tmp_path):
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0")
        rep = B.verify(out)
        assert rep.ok and not rep.signed and rep.name == "base"
        assert "base.yaml" in rep.files

    def test_invalid_policy_refused_at_pack_time(self, tmp_path):
        src = tmp_path / "bad"; src.mkdir()
        (src / "broken.yaml").write_text("version: 1\ntools: [this, is, wrong]\n")
        with pytest.raises(B.BundleError):
            B.pack(src, tmp_path / "b.wpb", name="bad", version="1.0")

    def test_tampered_member_fails_verification(self, policy_dir, tmp_path):
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0")
        # rewrite one member's bytes, leave the manifest alone
        tampered = tmp_path / "t.wpb"
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(tampered, "w") as zout:
            for item in zin.namelist():
                data = zin.read(item)
                if item == "base.yaml":
                    data += b"\n# attacker was here\n"
                zout.writestr(item, data)
        rep = B.verify(tampered)
        assert not rep.ok and any("hash mismatch" in p for p in rep.problems)
        with pytest.raises(B.BundleError):
            B.install(tampered, tmp_path / "dest", allow_unsigned=True)

    def test_undeclared_member_detected(self, policy_dir, tmp_path):
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0")
        smuggled = tmp_path / "s.wpb"
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(smuggled, "w") as zout:
            for item in zin.namelist():
                zout.writestr(item, zin.read(item))
            zout.writestr("extra.yaml", "version: 1\n")
        rep = B.verify(smuggled)
        assert not rep.ok and any("undeclared" in p for p in rep.problems)

    def test_unsigned_install_refused_by_default(self, policy_dir, tmp_path):
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0")
        with pytest.raises(B.BundleError, match="unsigned"):
            B.install(out, tmp_path / "dest")
        written = B.install(out, tmp_path / "dest", allow_unsigned=True)
        assert len(written) == 1 and written[0].name == "base.yaml"

    def test_traversal_member_rejected(self, tmp_path):
        evil = tmp_path / "evil.wpb"
        manifest = {"format": "warden-policy-bundle/1", "name": "x",
                    "version": "1", "files": {"../escape.yaml": "0" * 64}}
        with zipfile.ZipFile(evil, "w") as z:
            z.writestr("MANIFEST.json", json.dumps(manifest))
            z.writestr("../escape.yaml", "version: 1\n")
        with pytest.raises(B.BundleError, match="unsafe member"):
            B.verify(evil)

    @pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")
    def test_signed_roundtrip_and_wrong_key(self, policy_dir, tmp_path):
        B.keygen(tmp_path / "k.key", tmp_path / "k.pub")
        B.keygen(tmp_path / "other.key", tmp_path / "other.pub")
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0",
                     private_key_path=tmp_path / "k.key")
        good = B.verify(out, public_key_path=tmp_path / "k.pub")
        assert good.ok and good.signed and good.signature_valid
        bad = B.verify(out, public_key_path=tmp_path / "other.pub")
        assert not bad.ok and bad.signature_valid is False
        with pytest.raises(B.BundleError):
            B.install(out, tmp_path / "dest", public_key_path=tmp_path / "other.pub")
        assert B.install(out, tmp_path / "dest", public_key_path=tmp_path / "k.pub")

    @pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")
    def test_signed_bundle_without_key_refused(self, policy_dir, tmp_path):
        B.keygen(tmp_path / "k.key", tmp_path / "k.pub")
        out = B.pack(policy_dir, tmp_path / "b.wpb", name="base", version="1.0",
                     private_key_path=tmp_path / "k.key")
        with pytest.raises(B.BundleError, match="no public key"):
            B.install(out, tmp_path / "dest")

    @pytest.mark.skipif(HAVE_CRYPTO, reason="crypto installed; loud-failure path n/a")
    def test_missing_crypto_fails_loud(self, policy_dir, tmp_path):
        with pytest.raises(B.SigningUnavailable):
            B.keygen(tmp_path / "k.key", tmp_path / "k.pub")
        with pytest.raises(B.SigningUnavailable):
            B.pack(policy_dir, tmp_path / "b.wpb", name="x", version="1",
                   private_key_path=tmp_path / "nonexistent.key")


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #

@pytest.fixture
def dash(tmp_path, gate):
    # seed the audit corpus through the gate
    gate.call("read_file", lambda path: "ok", {"path": "notes.txt"})
    with pytest.raises(WardenDenied):
        gate.call("rm_rf", lambda **kw: None)
    policy = Path(gate.engine.policy_path if hasattr(gate.engine, "policy_path")
                  else tmp_path / "policy.yaml")
    server = DashboardServer(tmp_path / "policy.yaml", tmp_path / "audit.db", port=0)
    server.start()
    yield server
    server.stop()


def _get(server, route, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    headers = {"X-Warden-Token": token} if token else {}
    conn.request("GET", route, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, json.loads(body) if body.startswith(b"{") else body


def _post(server, route, body, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    headers = {"X-Warden-Token": token} if token else {}
    conn.request("POST", route, body=body.encode(), headers=headers)
    resp = conn.getresponse()
    out = json.loads(resp.read())
    conn.close()
    return resp.status, out


class TestDashboard:
    def test_binds_localhost_only(self, dash):
        assert dash._httpd.server_address[0] == "127.0.0.1"

    def test_no_token_is_401_everywhere(self, dash):
        for route in ("/", "/api/health", "/api/audit", "/api/telemetry",
                      "/api/sessions", "/api/policy"):
            status, _ = _get(dash, route)
            assert status == 401, f"{route} served without a token"
        status, _ = _post(dash, "/api/replay", "version: 1")
        assert status == 401

    def test_wrong_token_is_401(self, dash):
        status, _ = _get(dash, "/api/health", token="wrong-token")
        assert status == 401

    def test_health_audit_sessions_with_token(self, dash):
        status, health = _get(dash, "/api/health", token=dash.token)
        assert status == 200 and health["version"] == warden.__version__
        status, audit = _get(dash, "/api/audit", token=dash.token)
        assert status == 200
        assert audit["chain"].get("ok", True)
        decisions = {(r["tool"], r["decision"]) for r in audit["records"]}
        assert ("rm_rf", "DENY") in decisions
        status, sess = _get(dash, "/api/sessions", token=dash.token)
        assert status == 200 and sess["sessions"], "seeded calls must aggregate"
        assert sess["sessions"][0]["denied"] >= 1

    def test_validate_candidate_policy(self, dash, tmp_path):
        ws = tmp_path / "ws2"; ws.mkdir()
        good = MINI_POLICY.format(ws=ws)
        status, out = _post(dash, "/api/policy/validate", good, token=dash.token)
        assert status == 200 and out["valid"]
        status, out = _post(dash, "/api/policy/validate",
                            "version: 1\ntools: [broken]", token=dash.token)
        assert status == 200 and not out["valid"] and out["error"]

    def test_replay_candidate_reports_and_is_readonly(self, dash, tmp_path):
        live_before = (tmp_path / "policy.yaml").read_text()
        ws = tmp_path / "ws3"; ws.mkdir()
        stricter = ("version: 1\n"
                    f"workspace_root: '{ws}'\n"
                    "tools:\n"
                    "  read_file: {tier: escalate, path_args: [path]}\n")
        status, out = _post(dash, "/api/replay", stricter, token=dash.token)
        assert status == 200 and "summary" in out
        assert out["total"] >= 2
        assert (tmp_path / "policy.yaml").read_text() == live_before, \
            "replay must never touch the live policy"

    def test_replay_invalid_candidate_reports_error(self, dash):
        status, out = _post(dash, "/api/replay", "tools: [broken]",
                            token=dash.token)
        assert status == 200 and "error" in out

    def test_page_serves_with_token_and_has_no_external_requests(self, dash):
        status, body = _get(dash, f"/?token={dash.token}")
        assert status == 200
        html = body.decode()
        assert "Warden dashboard" in html
        assert "http://" not in html.replace("http://127.0.0.1", "") \
               and "https://" not in html, "page must load nothing external"
