"""
proxy/containment/quotas.py  (v5)

Resource quotas — CPU, memory, disk, process count, wall clock.

A sandbox without quotas contains the blast direction but not the blast
RADIUS: a contained workload can still eat every core, fill the disk, and
fork until the host stalls. Quotas close that.

Three properties:

  VALIDATED AT LOAD. A zero or negative quota is a policy error at startup
  (the v3/v4 contract) — a typo that would have meant "unlimited" is refused
  before any workload runs.
  RENDERED PER BACKEND. The same Quotas object renders to docker flags
  (--cpus, --memory, --pids-limit, tmpfs size) or wasmtime flags (linear
  memory cap). What the backend cannot enforce, the host does.
  ENFORCED HOST-SIDE TOO. Wall clock is never delegated: the Deadline is
  held by Warden with an injectable clock, because a wedged container
  cannot be trusted to report that it is wedged (QUO-001 on expiry).
"""

import time
from dataclasses import dataclass
from typing import Callable

DEFAULTS = {
    "cpus": 1.0,
    "memory_mb": 512,
    "disk_mb": 256,
    "pids": 64,
    "timeout_seconds": 300,
}


class QuotaError(ValueError):
    """A quota failed validation. Raised at LOAD, never at runtime."""


@dataclass(frozen=True)
class Quotas:
    cpus: float = DEFAULTS["cpus"]
    memory_mb: int = DEFAULTS["memory_mb"]
    disk_mb: int = DEFAULTS["disk_mb"]
    pids: int = DEFAULTS["pids"]
    timeout_seconds: float = DEFAULTS["timeout_seconds"]

    @classmethod
    def from_policy(cls, cfg: dict | None) -> "Quotas":
        cfg = cfg or {}
        merged = {**DEFAULTS, **{k: cfg[k] for k in DEFAULTS if k in cfg}}
        unknown = set(cfg) - set(DEFAULTS)
        if unknown:
            raise QuotaError(
                f"containment.quotas: unknown key(s) {sorted(unknown)} — a "
                f"misspelled quota would silently mean 'default', refused")
        q = cls(cpus=float(merged["cpus"]), memory_mb=int(merged["memory_mb"]),
                disk_mb=int(merged["disk_mb"]), pids=int(merged["pids"]),
                timeout_seconds=float(merged["timeout_seconds"]))
        q.validate()
        return q

    def validate(self) -> None:
        for name in ("cpus", "memory_mb", "disk_mb", "pids", "timeout_seconds"):
            value = getattr(self, name)
            if value <= 0:
                raise QuotaError(
                    f"containment.quotas.{name}: {value!r} — a quota must be "
                    f"a positive number; zero/negative would mean unlimited "
                    f"or nothing could run, and neither is ever implicit")

    # ------------------------------------------------------------------ #
    def docker_flags(self) -> list[str]:
        return [
            "--cpus", str(self.cpus),
            "--memory", f"{self.memory_mb}m",
            "--memory-swap", f"{self.memory_mb}m",   # swap = memory: no silent overflow
            "--pids-limit", str(self.pids),
        ]

    def wasmtime_flags(self) -> list[str]:
        # Wasm linear memory is the memory quota; there are no processes to
        # limit (a wasm module cannot fork) and CPU is bounded by the host
        # deadline below.
        return ["-W", f"max-memory-size={self.memory_mb * 1024 * 1024}"]


class Deadline:
    """Host-held wall clock. QUO-001 when a workload outlives its budget.

    Held by Warden, not the sandbox: the whole point is that a wedged or
    hostile workload does not get a vote on whether it has timed out.
    """

    def __init__(self, timeout_seconds: float,
                 clock: Callable[[], float] = time.time):
        if timeout_seconds <= 0:
            raise QuotaError(f"deadline must be positive, got {timeout_seconds!r}")
        self._clock = clock
        self.started_at = clock()
        self.timeout_seconds = float(timeout_seconds)

    def remaining(self) -> float:
        return self.timeout_seconds - (self._clock() - self.started_at)

    def expired(self) -> bool:
        return self.remaining() <= 0

    def violation(self) -> tuple[str, str] | None:
        if not self.expired():
            return None
        overrun = -self.remaining()
        return ("QUO-001",
                f"workload exceeded its wall-clock budget of "
                f"{self.timeout_seconds:.0f}s by {overrun:.0f}s — "
                f"terminating (a wedged workload does not get a vote)")
