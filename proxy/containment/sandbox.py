"""
proxy/containment/sandbox.py  (v5)

Sandbox provisioning — Warden creates the isolated environment. Not the
user, not the tool definition, not a config field somebody pasted from a
gist. The threat this answers is BYOS ("bring your own sandbox"): if the
workload's own configuration can describe the box it runs in, the box is
decoration.

The SandboxSpec is constructed ONLY from Warden's policy plus hardened
constants, and the constants are a FLOOR (SBX-002 to breach):

    network            "none". A v5 sandbox has no network, period. Outbound
                       access for tools goes through the v3 egress battery
                       at the proxy — the sandbox is not a second path.
    read-only rootfs   always. Writes go to the ephemeral workspace and a
                       size-capped noexec tmpfs, nowhere else.
    cap-drop ALL       always. no-new-privileges: always.
    quotas             always present (defaults if policy is silent), and
                       validated positive at load.

provision() ties the phase together: detect the ladder, select
required-or-stronger (SBX-001 on miss), build the floor-checked spec, and
render argv. Nothing here executes anything — the transport spawns the argv
it is handed, and every property of that argv is assertable in tests on a
machine with no container runtime at all.
"""

from dataclasses import dataclass, field
from typing import Callable

from proxy.containment import backends
from proxy.containment.quotas import Quotas

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_TMPFS_MB = 64


class SpecViolation(Exception):
    """An attempt to provision below the floor. Rule SBX-002."""


@dataclass(frozen=True)
class SandboxSpec:
    command: tuple
    image: str = DEFAULT_IMAGE
    workspace: str | None = None
    quotas: Quotas = field(default_factory=Quotas)
    tmpfs_size_mb: int = DEFAULT_TMPFS_MB
    wasm_module: str | None = None
    # Floor fields. They exist on the spec so renderers read them from one
    # place, but __post_init__ refuses any value other than the closed one —
    # there is no code path that produces an open spec.
    network: str = "none"
    read_only_root: bool = True
    cap_drop_all: bool = True
    no_new_privileges: bool = True

    def __post_init__(self):
        if self.network != "none":
            raise SpecViolation(
                f"SBX-002: sandbox network must be 'none', got "
                f"{self.network!r} — outbound access goes through the v3 "
                f"egress battery at the proxy, never through the sandbox")
        if not (self.read_only_root and self.cap_drop_all
                and self.no_new_privileges):
            raise SpecViolation(
                "SBX-002: read-only rootfs, cap-drop ALL, and "
                "no-new-privileges are the floor of every Warden sandbox "
                "and cannot be disabled by spec")
        if not self.command:
            raise SpecViolation("SBX-002: a sandbox needs a command to contain")
        if self.tmpfs_size_mb <= 0:
            raise SpecViolation(
                f"SBX-002: tmpfs_size_mb must be positive, got {self.tmpfs_size_mb!r}")


@dataclass
class ProvisionedSandbox:
    level: str
    argv: list[str]
    spec: SandboxSpec

    def audit_detail(self) -> dict:
        """What lands on the chain: enough to reconstruct the containment
        posture of the run without replaying the host."""
        return {
            "isolation": self.level,
            "image": self.spec.image,
            "network": self.spec.network,
            "read_only_root": self.spec.read_only_root,
            "cap_drop_all": self.spec.cap_drop_all,
            "quotas": {
                "cpus": self.spec.quotas.cpus,
                "memory_mb": self.spec.quotas.memory_mb,
                "pids": self.spec.quotas.pids,
                "timeout_seconds": self.spec.quotas.timeout_seconds,
            },
            "workspace": self.spec.workspace,
        }


def provision(command: list[str], cfg: dict | None = None,
              workspace: str | None = None,
              detector: Callable[[], dict] | None = None) -> ProvisionedSandbox:
    """Policy in, hardened argv out.

    cfg is the policy `containment:` block. The DETECTOR is injectable so
    the full ladder logic is testable host-free; the default probes the
    real host.
    """
    cfg = cfg or {}
    required = str(cfg.get("required_isolation", "docker"))
    allow_stronger = bool(cfg.get("allow_stronger", True))

    available = (detector or backends.detect)()
    level = backends.select_backend(required, available,
                                    allow_stronger=allow_stronger)

    spec = SandboxSpec(
        command=tuple(command),
        image=str(cfg.get("image", DEFAULT_IMAGE)),
        workspace=workspace,
        quotas=Quotas.from_policy(cfg.get("quotas")),
        tmpfs_size_mb=int(cfg.get("tmpfs_size_mb", DEFAULT_TMPFS_MB)),
        wasm_module=cfg.get("wasm_module"),
    )
    return ProvisionedSandbox(level=level, argv=backends.render(level, spec),
                              spec=spec)
