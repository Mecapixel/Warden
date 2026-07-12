"""
warden/containment/procmon.py  (v5)

Process monitor — what is the contained workload DOING with its process
table?

Quotas cap what a workload may consume; the monitor watches what it
actually does, because two workloads with identical resource footprints can
be one honest interpreter and one fork-bombing loader. Four signatures:

  PROC-001  fork breach — descendant count over budget. Fork bombs, but
            also quieter loaders that spawn workers to spread activity
            below per-process thresholds.
  PROC-002  zombie accumulation — children exited, parent never reaped.
            Sloppy code or deliberate pid-table exhaustion; either way over
            the budget it is a signal.
  PROC-003  overstay — the workload outlived its wall-clock budget. The
            monitor's clock is Warden's clock (injectable), never the
            workload's: a wedged process does not get a vote.
  PROC-004  unexpected executable — a descendant is running an image
            outside the declared allowlist. The contained Python tool that
            suddenly has a curl child is the canonical catch.

The process table arrives through an injectable snapshot provider. On a
Linux host the default provider walks /proc; in tests the provider is a
list, so every signature above is testable to the exact process on any OS.
Provider failure fails closed: no snapshot means MONITOR-BLIND, reported as
a violation, never as a quiet all-clear.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    state: str = "R"        # R/S/D running-ish, Z zombie
    exe: str = ""
    started_at: float = 0.0


@dataclass
class ProcViolation:
    rule: str
    detail: str
    pids: list[int] = field(default_factory=list)


def read_proc_snapshot() -> list[ProcInfo]:
    """Default provider: walk /proc. Linux only, by nature; every consumer
    accepts an injected provider precisely so nothing else needs this."""
    snapshot = []
    now = time.time()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(") ", 1)
            state, ppid = fields[1].split()[0], int(fields[1].split()[1])
            try:
                exe = str((entry / "exe").resolve())
            except OSError:
                exe = ""
            mtime = (entry / "stat").stat().st_mtime
            snapshot.append(ProcInfo(pid=int(entry.name), ppid=ppid,
                                     state=state, exe=exe,
                                     started_at=min(mtime, now)))
        except (OSError, ValueError, IndexError):
            continue    # a process that vanished mid-walk is not evidence
    return snapshot


class ProcessMonitor:
    """check(root_pid) -> violations, judged against one config.

    Config keys (all optional, each closed-by-default where absence would
    otherwise mean unlimited):
        max_children          descendant budget            (default 8)
        max_zombies           tolerated unreaped children  (default 0)
        max_runtime_seconds   wall clock for the root      (default 300)
        allowed_executables   glob list; absent = any      (default absent)
    """

    def __init__(self, cfg: dict | None = None,
                 snapshot_provider: Callable[[], list[ProcInfo]] | None = None,
                 clock: Callable[[], float] = time.time):
        cfg = cfg or {}
        self.max_children = int(cfg.get("max_children", 8))
        self.max_zombies = int(cfg.get("max_zombies", 0))
        self.max_runtime_seconds = float(cfg.get("max_runtime_seconds", 300))
        self.allowed_executables = cfg.get("allowed_executables")
        if self.max_children < 0 or self.max_zombies < 0 \
                or self.max_runtime_seconds <= 0:
            raise ValueError(
                "process_monitor budgets must be non-negative "
                "(runtime strictly positive) — a negative budget is a typo, "
                "not a policy")
        self._provider = snapshot_provider or read_proc_snapshot
        self._clock = clock

    # ------------------------------------------------------------------ #
    def descendants(self, root_pid: int,
                    snapshot: list[ProcInfo]) -> list[ProcInfo]:
        children: dict[int, list[ProcInfo]] = {}
        for proc in snapshot:
            children.setdefault(proc.ppid, []).append(proc)
        out, stack = [], [root_pid]
        while stack:
            for child in children.get(stack.pop(), []):
                out.append(child)
                stack.append(child.pid)
        return out

    def check(self, root_pid: int) -> list[ProcViolation]:
        try:
            snapshot = self._provider()
        except Exception as e:
            # A blind monitor is a violation, not an all-clear.
            return [ProcViolation(
                "PROC-000",
                f"process snapshot unavailable ({e!r}) — the monitor is "
                f"blind and blind is not clean (fail closed)")]

        violations: list[ProcViolation] = []
        root = next((p for p in snapshot if p.pid == root_pid), None)
        if root is None:
            return violations       # workload already gone; nothing to judge

        family = self.descendants(root_pid, snapshot)

        if len(family) > self.max_children:
            violations.append(ProcViolation(
                "PROC-001",
                f"{len(family)} descendants exceed the budget of "
                f"{self.max_children} — fork breach",
                pids=[p.pid for p in family]))

        zombies = [p for p in family if p.state == "Z"]
        if len(zombies) > self.max_zombies:
            violations.append(ProcViolation(
                "PROC-002",
                f"{len(zombies)} zombie process(es) exceed the tolerated "
                f"{self.max_zombies} — unreaped children accumulating",
                pids=[p.pid for p in zombies]))

        age = self._clock() - root.started_at
        if age > self.max_runtime_seconds:
            violations.append(ProcViolation(
                "PROC-003",
                f"workload has run {age:.0f}s against a budget of "
                f"{self.max_runtime_seconds:.0f}s — overstay",
                pids=[root_pid]))

        if self.allowed_executables is not None:
            import fnmatch
            for proc in [root, *family]:
                if proc.exe and not any(
                        fnmatch.fnmatchcase(proc.exe, pattern)
                        for pattern in self.allowed_executables):
                    violations.append(ProcViolation(
                        "PROC-004",
                        f"pid {proc.pid} is running {proc.exe!r}, outside "
                        f"the declared executable allowlist",
                        pids=[proc.pid]))

        return violations
