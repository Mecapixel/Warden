"""
warden/network/ratelimit.py  (v3)

In-process token-bucket rate limiting, global and per-tool.

Why a rate limiter belongs in a security gateway: a compromised or confused
agent does not need a novel exploit to do damage — a loop that fires
`http_get` five hundred times a minute is an exfiltration channel, a cost
bomb, and a DoS all at once. Volume itself is a signal. The bucket makes
the ceiling explicit, enforced, and audited (rule RATE-001).

Deliberately in-process (the roadmap's own note: 'Redis only if
multi-node'). A single-host gateway does not need a network hop to count
to ten, and adding one would put a new availability dependency in the
deny path.

The clock is injectable so tests control time instead of sleeping.
"""

import time
from typing import Callable


class TokenBucket:
    def __init__(self, capacity: float, refill_per_second: float,
                 clock: Callable[[], float] = time.monotonic):
        if capacity <= 0 or refill_per_second < 0:
            raise ValueError("capacity must be > 0 and refill_per_second >= 0")
        self.capacity = float(capacity)
        self.refill = float(refill_per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()

    def try_acquire(self, cost: float = 1.0) -> bool:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.refill)
        self._last = now
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False


class RateLimiter:
    """Global bucket plus optional per-tool buckets, built from policy.

    Config shape (policy.yaml -> network.rate_limit):
        enabled: true
        global: {capacity: 60, refill_per_second: 1}
        per_tool:
          http_get: {capacity: 10, refill_per_second: 0.2}

    A call must clear BOTH its tool bucket (if declared) and the global
    bucket. Order matters: the tool bucket is checked first so a noisy tool
    exhausts its own budget before it can starve quiet tools of the global
    one.
    """

    def __init__(self, cfg: dict | None, clock: Callable[[], float] = time.monotonic):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self._clock = clock
        g = cfg.get("global") or {}
        self._global = TokenBucket(
            g.get("capacity", 120), g.get("refill_per_second", 2), clock
        ) if self.enabled else None
        self._per_tool: dict[str, TokenBucket] = {}
        for tool, spec in (cfg.get("per_tool") or {}).items():
            self._per_tool[tool] = TokenBucket(
                spec.get("capacity", 10), spec.get("refill_per_second", 0.5), clock
            )

    def acquire(self, tool: str) -> tuple[bool, str | None]:
        """Returns (ok, reason). reason is set only on refusal."""
        if not self.enabled:
            return True, None
        bucket = self._per_tool.get(tool)
        if bucket and not bucket.try_acquire():
            return False, f"per-tool rate limit exceeded for {tool!r}"
        if self._global and not self._global.try_acquire():
            return False, "global rate limit exceeded"
        return True, None
