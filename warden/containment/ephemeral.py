"""
warden/containment/ephemeral.py  (v5)

Ephemeral filesystem — nothing a workload writes survives the workload.

Persistence is the attacker's friend twice over: a compromised run that can
leave a file behind has a foothold for the NEXT run (the v4 session-wipe
lesson, extended to containment), and artifacts on disk after death are
exfiltration staging. So the sandbox's writable surface is built to die:

  OVERLAY MODE   on a Linux host with mount privileges, the workspace is an
                 OverlayFS: the real directory is the read-only lowerdir,
                 writes land in an upperdir under a per-run temp root, and
                 destroying the run deletes upper+work in one stroke. The
                 lower layer is PROVABLY untouched because overlay never
                 writes to it. This module renders the mount spec; executing
                 it belongs to the host integration, not to library code.

  STAGING MODE   everywhere else (Windows hosts, unprivileged runs): a
                 fresh per-run staging directory is the writable workspace,
                 destroyed after execution. Weaker than overlay (no
                 read-only lower layer underneath) and the audit record SAYS
                 so — mode is recorded, never blurred.

Destruction is VERIFIED, not assumed: destroy() re-checks the tree after
removal and anything still present is an EPH-001 violation with the
survivors named. "I deleted it" is a claim; an empty directory is evidence.
"""

import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DestroyReport:
    mode: str
    destroyed: bool
    leftovers: list[str] = field(default_factory=list)
    rule: str | None = None
    detail: str | None = None


class EphemeralWorkspace:
    """A writable surface with a scheduled death.

    mode='staging' (default, works everywhere) or mode='overlay' (renders a
    Linux OverlayFS mount over `lower`). Paths are created at construction;
    `destroy()` is idempotent and returns a verified report.
    """

    def __init__(self, root: str, mode: str = "staging",
                 lower: str | None = None):
        if mode not in ("staging", "overlay"):
            raise ValueError(f"ephemeral mode {mode!r} is not 'staging' or 'overlay'")
        if mode == "overlay" and not lower:
            raise ValueError("overlay mode needs a lowerdir (the read-only base)")
        self.mode = mode
        self.lower = lower
        self.run_id = f"E-{secrets.token_hex(6)}"
        self._root = Path(root) / self.run_id
        self.destroyed = False

        if mode == "overlay":
            self.upper = self._root / "upper"
            self.work = self._root / "work"
            self.mount_point = self._root / "merged"
            for p in (self.upper, self.work, self.mount_point):
                p.mkdir(parents=True, exist_ok=False)
            self.workspace = str(self.mount_point)
        else:
            self.staging = self._root / "workspace"
            self.staging.mkdir(parents=True, exist_ok=False)
            self.workspace = str(self.staging)

    # ------------------------------------------------------------------ #
    def overlay_mount_argv(self) -> list[str]:
        """The rendered mount command for overlay mode. Rendered, not run —
        the transport/host integration executes it with whatever privilege
        model the deployment uses, and tests assert the spec."""
        if self.mode != "overlay":
            raise RuntimeError("mount argv only exists in overlay mode")
        return [
            "mount", "-t", "overlay", "overlay",
            "-o", (f"lowerdir={self.lower},"
                   f"upperdir={self.upper},"
                   f"workdir={self.work}"),
            str(self.mount_point),
        ]

    def overlay_unmount_argv(self) -> list[str]:
        if self.mode != "overlay":
            raise RuntimeError("unmount argv only exists in overlay mode")
        return ["umount", str(self.mount_point)]

    # ------------------------------------------------------------------ #
    def destroy(self) -> DestroyReport:
        """Remove the run root and VERIFY it is gone. Idempotent."""
        if self.destroyed:
            return DestroyReport(self.mode, True, detail="already destroyed")
        self.destroyed = True

        shutil.rmtree(self._root, ignore_errors=True)

        if not self._root.exists():
            return DestroyReport(self.mode, True)

        # Something survived. Name every survivor — an EPH-001 report that
        # says "cleanup failed" without saying WHAT survived would leave the
        # operator hunting for the foothold this module exists to prevent.
        leftovers = sorted(
            str(p.relative_to(self._root))
            for p in self._root.rglob("*"))
        return DestroyReport(
            self.mode, False, leftovers=leftovers, rule="EPH-001",
            detail=(f"ephemeral workspace {self.run_id} was not fully "
                    f"destroyed; {len(leftovers)} artifact(s) survived — "
                    f"treat as a persistence attempt until proven otherwise"))
