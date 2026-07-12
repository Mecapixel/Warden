"""
tests/test_v5_containment.py

v5 — Runtime Containment. The isolation ladder with injected detection,
sandbox provisioning against a non-negotiable floor, verified-destruction
ephemeral workspaces, load-validated quotas with a host-held deadline, and
the process monitor against injected process tables.

Nothing in this suite touches a real container runtime, mounts a real
overlay, or reads a real /proc: detection is injected, argv is asserted as
data, and process snapshots are lists. A machine with no Docker daemon runs
every test — which is the point of the design being tested.
"""

import pytest

from warden.containment.backends import (
    BackendUnavailable, ISOLATION_ORDER, detect, select_backend,
    render, render_docker, render_wasmtime)
from warden.containment.sandbox import (
    SandboxSpec, SpecViolation, provision, DEFAULT_IMAGE)
from warden.containment.ephemeral import EphemeralWorkspace
from warden.containment.quotas import Quotas, QuotaError, Deadline
from warden.containment.procmon import ProcessMonitor, ProcInfo
from warden.policy.engine import PolicyEngine, PolicyValidationError


NONE_AVAILABLE = {"docker": False, "gvisor": False, "wasmtime": False}
ALL_AVAILABLE = {"docker": True, "gvisor": True, "wasmtime": True}


# ---------------------------------------------------------------------------
# backends — detection and the ladder
# ---------------------------------------------------------------------------
class TestDetection:
    def test_detects_full_ladder(self):
        def runner(argv):
            if argv[:2] == ["docker", "version"]:
                return 0, "27.0.1"
            if argv[:2] == ["docker", "info"]:
                return 0, "map[io.containerd.runc.v2:{} runsc:{}]"
            if argv[0] == "wasmtime":
                return 0, "wasmtime 24.0.0"
            return 1, ""
        found = detect(runner=runner, which=lambda name: f"/usr/bin/{name}")
        assert found == ALL_AVAILABLE

    def test_docker_without_runsc_is_not_gvisor(self):
        def runner(argv):
            if argv[:2] == ["docker", "version"]:
                return 0, "27.0.1"
            if argv[:2] == ["docker", "info"]:
                return 0, "map[io.containerd.runc.v2:{}]"
            return 1, ""
        found = detect(runner=runner, which=lambda n: "/usr/bin/docker" if n == "docker" else None)
        assert found == {"docker": True, "gvisor": False, "wasmtime": False}

    def test_missing_binaries_detect_nothing(self):
        found = detect(runner=lambda argv: (1, ""), which=lambda n: None)
        assert found == NONE_AVAILABLE

    def test_daemon_down_is_unavailable(self):
        # The CLI exists but the daemon refuses: that host has no docker rung.
        found = detect(runner=lambda argv: (1, "Cannot connect to the Docker daemon"),
                       which=lambda n: "/usr/bin/docker" if n == "docker" else None)
        assert not found["docker"] and not found["gvisor"]


class TestLadderSelection:
    def test_exact_rung_selected(self):
        assert select_backend("docker", {"docker": True, "gvisor": False,
                                         "wasmtime": False}) == "docker"

    def test_climbs_to_stronger_when_required_missing(self):
        assert select_backend("docker", {"docker": False, "gvisor": True,
                                         "wasmtime": False}) == "gvisor"
        assert select_backend("docker", {"docker": False, "gvisor": False,
                                         "wasmtime": True}) == "wasmtime"

    def test_never_descends_to_weaker(self):
        with pytest.raises(BackendUnavailable) as e:
            select_backend("gvisor", {"docker": True, "gvisor": False,
                                      "wasmtime": False})
        assert "SBX-001" in str(e.value)

    def test_allow_stronger_false_pins_the_rung(self):
        with pytest.raises(BackendUnavailable):
            select_backend("docker", {"docker": False, "gvisor": True,
                                      "wasmtime": True}, allow_stronger=False)

    def test_nothing_available_fails_loud(self):
        with pytest.raises(BackendUnavailable) as e:
            select_backend("docker", NONE_AVAILABLE)
        assert "SBX-001" in str(e.value)

    def test_unknown_level_refused(self):
        with pytest.raises(BackendUnavailable):
            select_backend("chroot", ALL_AVAILABLE)

    def test_ladder_order_is_the_contract(self):
        assert ISOLATION_ORDER == ["docker", "gvisor", "wasmtime"]


# ---------------------------------------------------------------------------
# rendering — the argv IS the security posture
# ---------------------------------------------------------------------------
def spec(**kw):
    kw.setdefault("command", ("python", "server.py"))
    return SandboxSpec(**kw)


class TestDockerRendering:
    def test_hardened_flags_always_present(self):
        argv = render_docker(spec(workspace="/tmp/ws"))
        joined = " ".join(argv)
        assert "--network none" in joined
        assert "--read-only" in joined
        assert "--cap-drop ALL" in joined
        assert "--security-opt no-new-privileges" in joined
        assert "--rm" in argv and "--init" in argv

    def test_tmpfs_is_noexec_and_size_capped(self):
        argv = render_docker(spec(tmpfs_size_mb=32))
        tmpfs = argv[argv.index("--tmpfs") + 1]
        assert "noexec" in tmpfs and "nosuid" in tmpfs and "size=32m" in tmpfs

    def test_quota_flags_rendered(self):
        argv = render_docker(spec(quotas=Quotas(cpus=2.0, memory_mb=256,
                                                pids=32)))
        joined = " ".join(argv)
        assert "--cpus 2.0" in joined
        assert "--memory 256m" in joined
        assert "--memory-swap 256m" in joined      # swap = memory: no overflow
        assert "--pids-limit 32" in joined

    def test_command_lands_after_image(self):
        argv = render_docker(spec(image="python:3.12-slim",
                                  command=("python", "-m", "srv")))
        i = argv.index("python:3.12-slim")
        assert argv[i + 1:] == ["python", "-m", "srv"]

    def test_gvisor_is_docker_plus_runsc(self):
        docker = render("docker", spec())
        gvisor = render("gvisor", spec())
        assert "--runtime" not in docker
        assert gvisor[gvisor.index("--runtime") + 1] == "runsc"
        assert [a for a in gvisor if a not in ("--runtime", "runsc")] == docker


class TestWasmtimeRendering:
    def test_wasm_module_required(self):
        with pytest.raises(BackendUnavailable) as e:
            render_wasmtime(spec())
        assert "SBX-001" in str(e.value) and "wasm_module" in str(e.value)

    def test_renders_module_dir_and_memory(self):
        argv = render_wasmtime(spec(wasm_module="server.wasm",
                                    workspace="/tmp/ws",
                                    quotas=Quotas(memory_mb=128)))
        assert argv[:2] == ["wasmtime", "run"]
        assert "server.wasm" in argv
        assert f"max-memory-size={128 * 1024 * 1024}" in " ".join(argv)
        assert "/tmp/ws::/workspace" in " ".join(argv)


# ---------------------------------------------------------------------------
# sandbox — the floor is not negotiable
# ---------------------------------------------------------------------------
class TestSandboxFloor:
    def test_network_cannot_be_opened(self):
        with pytest.raises(SpecViolation) as e:
            spec(network="bridge")
        assert "SBX-002" in str(e.value)

    def test_read_only_root_cannot_be_disabled(self):
        with pytest.raises(SpecViolation):
            spec(read_only_root=False)

    def test_cap_drop_cannot_be_disabled(self):
        with pytest.raises(SpecViolation):
            spec(cap_drop_all=False)

    def test_no_new_privileges_cannot_be_disabled(self):
        with pytest.raises(SpecViolation):
            spec(no_new_privileges=False)

    def test_empty_command_refused(self):
        with pytest.raises(SpecViolation):
            SandboxSpec(command=())

    def test_nonpositive_tmpfs_refused(self):
        with pytest.raises(SpecViolation):
            spec(tmpfs_size_mb=0)


class TestProvisioning:
    def test_policy_in_hardened_argv_out(self):
        p = provision(["python", "srv.py"],
                      cfg={"required_isolation": "docker",
                           "quotas": {"memory_mb": 128}},
                      workspace="/tmp/ws",
                      detector=lambda: dict(ALL_AVAILABLE))
        assert p.level == "docker"
        assert "--network" in p.argv and "none" in p.argv
        assert "--memory 128m" in " ".join(p.argv)
        assert p.argv[-2:] == ["python", "srv.py"]

    def test_provision_climbs_the_ladder(self):
        p = provision(["python", "srv.py"],
                      cfg={"required_isolation": "docker"},
                      detector=lambda: {"docker": False, "gvisor": True,
                                        "wasmtime": False})
        assert p.level == "gvisor" and "runsc" in p.argv

    def test_provision_refuses_weaker_host(self):
        with pytest.raises(BackendUnavailable):
            provision(["python", "srv.py"],
                      cfg={"required_isolation": "gvisor"},
                      detector=lambda: {"docker": True, "gvisor": False,
                                        "wasmtime": False})

    def test_defaults_are_the_closed_ones(self):
        p = provision(["srv"], cfg={}, detector=lambda: dict(ALL_AVAILABLE))
        assert p.spec.image == DEFAULT_IMAGE
        assert p.spec.network == "none"
        assert p.spec.quotas.memory_mb == 512      # defaults, not unlimited

    def test_audit_detail_reconstructs_posture(self):
        p = provision(["srv"], cfg={}, workspace="/tmp/ws",
                      detector=lambda: dict(ALL_AVAILABLE))
        d = p.audit_detail()
        assert d["isolation"] == "docker" and d["network"] == "none"
        assert d["read_only_root"] and d["cap_drop_all"]
        assert d["quotas"]["timeout_seconds"] == 300


# ---------------------------------------------------------------------------
# ephemeral — the writable surface dies, verifiably
# ---------------------------------------------------------------------------
class TestEphemeral:
    def test_staging_created_fresh_and_destroyed(self, tmp_path):
        e = EphemeralWorkspace(str(tmp_path / "runs"))
        ws = e.workspace
        (tmp_path / "runs" / e.run_id / "workspace" / "scratch.txt").write_text("x")
        report = e.destroy()
        assert report.destroyed and report.rule is None
        import os
        assert not os.path.exists(ws)

    def test_destroy_is_idempotent(self, tmp_path):
        e = EphemeralWorkspace(str(tmp_path / "runs"))
        assert e.destroy().destroyed
        again = e.destroy()
        assert again.destroyed and again.detail == "already destroyed"

    def test_run_ids_isolate_concurrent_runs(self, tmp_path):
        a = EphemeralWorkspace(str(tmp_path / "runs"))
        b = EphemeralWorkspace(str(tmp_path / "runs"))
        assert a.workspace != b.workspace
        a.destroy()
        import os
        assert os.path.exists(b.workspace)     # b unharmed by a's death

    def test_overlay_mode_renders_mount_spec(self, tmp_path):
        e = EphemeralWorkspace(str(tmp_path / "runs"), mode="overlay",
                               lower=str(tmp_path / "base"))
        argv = e.overlay_mount_argv()
        opts = argv[argv.index("-o") + 1]
        assert argv[:4] == ["mount", "-t", "overlay", "overlay"]
        assert f"lowerdir={tmp_path / 'base'}" in opts
        assert str(e.upper) in opts and str(e.work) in opts
        assert e.overlay_unmount_argv() == ["umount", str(e.mount_point)]

    def test_overlay_requires_a_lower_layer(self, tmp_path):
        with pytest.raises(ValueError):
            EphemeralWorkspace(str(tmp_path / "runs"), mode="overlay")

    def test_unknown_mode_refused(self, tmp_path):
        with pytest.raises(ValueError):
            EphemeralWorkspace(str(tmp_path / "runs"), mode="yolo")

    def test_survivors_are_eph001_and_named(self, tmp_path, monkeypatch):
        e = EphemeralWorkspace(str(tmp_path / "runs"))
        (tmp_path / "runs" / e.run_id / "workspace" / "persist.bin").write_text("x")
        import shutil as _shutil
        monkeypatch.setattr(_shutil, "rmtree",
                            lambda *a, **k: None)      # the wipe "fails"
        report = e.destroy()
        assert not report.destroyed and report.rule == "EPH-001"
        assert any("persist.bin" in leftover for leftover in report.leftovers)
        assert "persistence attempt" in report.detail


# ---------------------------------------------------------------------------
# quotas — validated at load, deadline held by the host
# ---------------------------------------------------------------------------
class TestQuotas:
    def test_defaults_applied_and_overridable(self):
        q = Quotas.from_policy({"memory_mb": 128})
        assert q.memory_mb == 128 and q.cpus == 1.0 and q.pids == 64

    def test_zero_or_negative_refused_at_load(self):
        for bad in ({"cpus": 0}, {"memory_mb": -1}, {"pids": 0},
                    {"timeout_seconds": 0}, {"disk_mb": -5}):
            with pytest.raises(QuotaError):
                Quotas.from_policy(bad)

    def test_unknown_key_refused_at_load(self):
        # A misspelled quota silently meaning "default" is exactly the
        # containing-less-than-written failure the load check exists for.
        with pytest.raises(QuotaError) as e:
            Quotas.from_policy({"memroy_mb": 128})
        assert "memroy_mb" in str(e.value)

    def test_deadline_with_injected_clock(self):
        t = [100.0]
        d = Deadline(30, clock=lambda: t[0])
        assert not d.expired() and d.remaining() == 30
        t[0] = 131.0
        assert d.expired()
        rule, detail = d.violation()
        assert rule == "QUO-001" and "does not get a vote" in detail

    def test_unexpired_deadline_has_no_violation(self):
        assert Deadline(30, clock=lambda: 0.0).violation() is None

    def test_nonpositive_deadline_refused(self):
        with pytest.raises(QuotaError):
            Deadline(0)


# ---------------------------------------------------------------------------
# procmon — judged against injected process tables
# ---------------------------------------------------------------------------
def table(*procs):
    return lambda: list(procs)


ROOT = ProcInfo(pid=100, ppid=1, state="S", exe="/usr/bin/python3",
                started_at=0.0)


class TestProcessMonitor:
    def test_quiet_family_is_clean(self):
        m = ProcessMonitor({"max_children": 4},
                           snapshot_provider=table(
                               ROOT,
                               ProcInfo(101, 100, "S", "/usr/bin/python3")),
                           clock=lambda: 10.0)
        assert m.check(100) == []

    def test_fork_breach_proc001_names_the_family(self):
        kids = [ProcInfo(101 + i, 100, "S", "/bin/sh") for i in range(5)]
        m = ProcessMonitor({"max_children": 2},
                           snapshot_provider=table(ROOT, *kids),
                           clock=lambda: 1.0)
        v = m.check(100)
        assert any(x.rule == "PROC-001" and len(x.pids) == 5 for x in v)

    def test_grandchildren_count_against_the_budget(self):
        # A loader that forks through an intermediary is still a fork breach.
        chain = [ProcInfo(101, 100), ProcInfo(102, 101), ProcInfo(103, 102)]
        m = ProcessMonitor({"max_children": 2},
                           snapshot_provider=table(ROOT, *chain),
                           clock=lambda: 1.0)
        assert any(x.rule == "PROC-001" for x in m.check(100))

    def test_zombies_proc002_default_zero_tolerance(self):
        m = ProcessMonitor({},
                           snapshot_provider=table(
                               ROOT, ProcInfo(101, 100, state="Z")),
                           clock=lambda: 1.0)
        v = m.check(100)
        assert any(x.rule == "PROC-002" and x.pids == [101] for x in v)

    def test_overstay_proc003_uses_wardens_clock(self):
        m = ProcessMonitor({"max_runtime_seconds": 60},
                           snapshot_provider=table(ROOT),
                           clock=lambda: 61.0)
        assert any(x.rule == "PROC-003" for x in m.check(100))

    def test_unexpected_executable_proc004(self):
        m = ProcessMonitor({"allowed_executables": ["/usr/bin/python*"],
                            "max_children": 8},
                           snapshot_provider=table(
                               ROOT, ProcInfo(101, 100, exe="/usr/bin/curl")),
                           clock=lambda: 1.0)
        v = m.check(100)
        assert any(x.rule == "PROC-004" and x.pids == [101] for x in v)

    def test_no_allowlist_means_any_executable(self):
        m = ProcessMonitor({"max_children": 8},
                           snapshot_provider=table(
                               ROOT, ProcInfo(101, 100, exe="/usr/bin/curl")),
                           clock=lambda: 1.0)
        assert m.check(100) == []

    def test_vanished_root_is_nothing_to_judge(self):
        m = ProcessMonitor({}, snapshot_provider=table(), clock=lambda: 1.0)
        assert m.check(100) == []

    def test_blind_monitor_fails_closed(self):
        def broken():
            raise OSError("no /proc here")
        m = ProcessMonitor({}, snapshot_provider=broken)
        v = m.check(100)
        assert len(v) == 1 and v[0].rule == "PROC-000" and "blind" in v[0].detail

    def test_negative_budgets_refused(self):
        with pytest.raises(ValueError):
            ProcessMonitor({"max_children": -1}, snapshot_provider=table())
        with pytest.raises(ValueError):
            ProcessMonitor({"max_runtime_seconds": 0}, snapshot_provider=table())


# ---------------------------------------------------------------------------
# policy validation — bad containment config refused at load
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

    def test_unknown_isolation_level_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path, "containment: {required_isolation: chroot}\n")

    def test_wasmtime_without_module_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "containment: {enabled: true, required_isolation: wasmtime}\n")

    def test_bad_quota_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "containment:\n  quotas: {memory_mb: 0}\n")

    def test_misspelled_quota_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "containment:\n  quotas: {memroy_mb: 128}\n")

    def test_bad_process_monitor_rejected(self, tmp_path):
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "containment:\n  process_monitor: {max_children: -2}\n")

    def test_valid_block_loads(self, tmp_path):
        eng = self._load(tmp_path,
                         "containment:\n  enabled: false\n"
                         "  required_isolation: gvisor\n"
                         "  quotas: {memory_mb: 128}\n")
        assert eng.policy["containment"]["required_isolation"] == "gvisor"

    def test_absent_block_changes_nothing(self, tmp_path):
        eng = self._load(tmp_path, "")
        assert "containment" not in eng.policy or not eng.policy.get("containment")


# ---------------------------------------------------------------------------
# transport integration — the sandbox wraps the spawn and lands on the chain
# ---------------------------------------------------------------------------
class TestTransportIntegration:
    def test_proxy_spawns_the_sandbox_argv(self, tmp_path):
        from warden.audit.log import AuditLog
        from warden.runtime.mediator import Mediator
        from warden.runtime.approval import ApprovalGate
        from warden.transport.mcp import MCPProxy

        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools:\n  read_file: {tier: auto}\n")
        engine = PolicyEngine(str(policy))
        audit = AuditLog(str(tmp_path / "audit.db"))
        med = Mediator(engine, audit, approval=ApprovalGate(asker=lambda _: "n"))

        p = provision(["python", "srv.py"], cfg={}, workspace=str(tmp_path),
                      detector=lambda: dict(ALL_AVAILABLE))
        wproxy = MCPProxy(med, ["python", "srv.py"], sandbox=p)

        assert wproxy.server_cmd == p.argv          # the sandbox IS the spawn
        assert wproxy.server_cmd[:2] == ["docker", "run"]

        rows = list(audit._conn.execute(
            "SELECT decision, detail FROM audit WHERE decision = 'SANDBOX_PROVISIONED'"))
        assert len(rows) == 1 and '"isolation": "docker"' in rows[0][1]
        audit.close()

    def test_proxy_without_sandbox_unchanged(self, tmp_path):
        from warden.audit.log import AuditLog
        from warden.runtime.mediator import Mediator
        from warden.runtime.approval import ApprovalGate
        from warden.transport.mcp import MCPProxy

        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            "tools:\n  read_file: {tier: auto}\n")
        engine = PolicyEngine(str(policy))
        audit = AuditLog(str(tmp_path / "audit.db"))
        med = Mediator(engine, audit, approval=ApprovalGate(asker=lambda _: "n"))
        wproxy = MCPProxy(med, ["python", "srv.py"])
        assert wproxy.server_cmd == ["python", "srv.py"]
        audit.close()
