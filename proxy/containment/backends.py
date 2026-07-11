"""
proxy/containment/backends.py  (v5)

The isolation ladder — Docker -> gVisor -> Wasmtime, in increasing order of
isolation strength.

  DOCKER     namespace/cgroup isolation with a shared host kernel. The
             baseline: strong enough for resource containment and filesystem
             /network isolation, but a kernel exploit escapes it.
  GVISOR     Docker with the runsc runtime — a userspace kernel between the
             workload and the host kernel. Syscalls terminate in gVisor, not
             the host; the escape surface shrinks to gVisor's much smaller
             host-syscall footprint.
  WASMTIME   no kernel at all from the workload's point of view. A wasm
             module gets linear memory and exactly the WASI capabilities it
             was handed; there is no ambient filesystem, network, or process
             table to escape INTO. Strongest isolation, narrowest workload
             support (the workload must be a wasm module).

Two laws, both the same laws the rest of Warden lives by:

  FAIL LOUD. Policy declares `required_isolation`. If that backend is not
  available on this host, provisioning refuses (SBX-001) — Warden never
  quietly runs a workload with weaker isolation than the operator wrote
  down. `allow_stronger: true` lets provisioning pick a STRONGER available
  rung; nothing ever selects a weaker one.

  TESTABLE WITHOUT THE BACKEND. Detection shells out through an injectable
  runner and rendering produces argv lists without executing anything, so
  every property of the generated sandbox — network none, cap-drop ALL,
  read-only root, quota flags — is assertable in tests on any machine,
  including machines with no Docker daemon at all. Same philosophy as v3's
  injected DNS resolvers.
"""

import shutil
import subprocess
from typing import Callable

# Weakest to strongest. Position IS the isolation ordering.
ISOLATION_ORDER = ["docker", "gvisor", "wasmtime"]


class BackendUnavailable(Exception):
    """The isolation the operator required does not exist on this host.
    Raised at provision time — never discovered mid-workload. Rule SBX-001."""


def _default_runner(argv: list[str]) -> tuple[int, str]:
    """Run a detection probe. Only ever used for read-only version/info
    probes; sandbox argv itself is executed by the transport, not here."""
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return out.returncode, (out.stdout or "") + (out.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, repr(e)


def detect(runner: Callable[[list[str]], tuple[int, str]] | None = None,
           which: Callable[[str], str | None] = shutil.which) -> dict[str, bool]:
    """What rungs of the ladder exist on this host?

    docker:   the docker CLI answers `docker version`.
    gvisor:   docker is available AND `docker info` lists the runsc runtime.
    wasmtime: the wasmtime CLI answers `--version`.
    """
    run = runner or _default_runner
    available = {"docker": False, "gvisor": False, "wasmtime": False}

    if which("docker") is not None:
        code, _ = run(["docker", "version", "--format", "{{.Server.Version}}"])
        available["docker"] = code == 0
        if available["docker"]:
            code, text = run(["docker", "info", "--format", "{{.Runtimes}}"])
            available["gvisor"] = code == 0 and "runsc" in text

    if which("wasmtime") is not None:
        code, _ = run(["wasmtime", "--version"])
        available["wasmtime"] = code == 0

    return available


def select_backend(required: str, available: dict[str, bool],
                   allow_stronger: bool = True) -> str:
    """Pick the rung. Required-or-stronger, never weaker (SBX-001 on miss)."""
    req = (required or "").strip().lower()
    if req not in ISOLATION_ORDER:
        raise BackendUnavailable(
            f"SBX-001: required_isolation {required!r} is not a known level "
            f"(choose from {ISOLATION_ORDER})")

    floor = ISOLATION_ORDER.index(req)
    candidates = ISOLATION_ORDER[floor:] if allow_stronger else [req]
    for level in candidates:
        if available.get(level):
            return level

    raise BackendUnavailable(
        f"SBX-001: policy requires isolation {req!r}"
        f"{' (or stronger)' if allow_stronger else ''} but this host offers "
        f"{[k for k, v in available.items() if v] or 'none of the ladder'}. "
        f"Warden will not run the workload with weaker isolation than the "
        f"operator configured — install the backend or lower the policy "
        f"deliberately.")


# --------------------------------------------------------------------------- #
# Rendering — spec to argv, nothing executed here
# --------------------------------------------------------------------------- #
def render_docker(spec, runtime: str | None = None) -> list[str]:
    """The hardened docker invocation. Every default is the closed one and
    the caller cannot reach this function except through a SandboxSpec that
    enforces the floor (see sandbox.py)."""
    argv = ["docker", "run", "--rm", "--init"]
    if runtime:
        argv += ["--runtime", runtime]
    argv += [
        "--network", spec.network,                    # floor-enforced: "none"
        "--read-only",                                # rootfs is immutable
        "--cap-drop", "ALL",                          # no capabilities at all
        "--security-opt", "no-new-privileges",        # setuid dead ends here
    ]
    argv += ["--tmpfs", f"/tmp:rw,noexec,nosuid,size={spec.tmpfs_size_mb}m"]
    if spec.workspace:
        argv += ["--mount",
                 f"type=bind,source={spec.workspace},target=/workspace"]
        argv += ["--workdir", "/workspace"]
    argv += spec.quotas.docker_flags()
    argv += [spec.image]
    argv += list(spec.command)
    return argv


def render_wasmtime(spec) -> list[str]:
    """Wasmtime invocation. The workload must BE a wasm module — there is no
    'run this arbitrary binary in wasm' and pretending otherwise would be
    exactly the silent downgrade this module exists to prevent."""
    if not spec.wasm_module:
        raise BackendUnavailable(
            "SBX-001: wasmtime isolation selected but the workload declares "
            "no wasm_module — a native command cannot run on the wasm rung; "
            "lower required_isolation deliberately or ship a wasm build")
    argv = ["wasmtime", "run"]
    if spec.workspace:
        argv += ["--dir", f"{spec.workspace}::/workspace"]
    argv += spec.quotas.wasmtime_flags()
    argv += [spec.wasm_module]
    argv += list(spec.command)
    return argv


def render(level: str, spec) -> list[str]:
    if level == "docker":
        return render_docker(spec)
    if level == "gvisor":
        return render_docker(spec, runtime="runsc")
    if level == "wasmtime":
        return render_wasmtime(spec)
    raise BackendUnavailable(f"SBX-001: unknown isolation level {level!r}")
