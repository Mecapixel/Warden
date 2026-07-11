"""
proxy/network/reputation.py  (v3)

Domain reputation cache — known-good / known-bad / unknown.

Reputation is defense-in-depth, never the wall: the allowlist and SSRF
checks decide reachability; reputation adds a second opinion that can
harden the verdict (known-bad denies even an allowlisted host — an operator
who allowlisted '*.example-cdn.net' last year gets protection when one
subdomain turns up on a blocklist) and can gate the long tail (unknown
hosts escalate or deny per policy).

Sources are operator-declared lists in policy plus a runtime cache with
TTL, so a deployment can feed verdicts in from threat intel without Warden
growing a network dependency of its own — a security gateway that phones
home to third-party APIs on every decision has quietly added a new trust
boundary. Persistence is a plain JSON file, human-readable and diffable.

Precedence: known_bad beats known_good beats cache beats unknown. A host
on both lists is a configuration mistake that must resolve to the safe
answer, never the convenient one.
"""

import json
import time
from pathlib import Path
from typing import Callable


def _match(host: str, entries: list[str]) -> bool:
    h = host.lower().rstrip(".")
    for entry in entries or []:
        e = entry.lower().rstrip(".")
        if e.startswith("*."):
            if h.endswith(e[1:]) and h != e[2:]:
                return True
        elif h == e:
            return True
    return False


class ReputationCache:
    def __init__(self, known_good: list[str] | None = None,
                 known_bad: list[str] | None = None,
                 cache_path: str | None = None,
                 ttl_seconds: int = 86400,
                 clock: Callable[[], float] = time.time):
        self.known_good = list(known_good or [])
        self.known_bad = list(known_bad or [])
        self.ttl = ttl_seconds
        self._clock = clock
        self._cache: dict[str, tuple[str, float]] = {}   # host -> (status, expiry)
        self._path = Path(cache_path) if cache_path else None
        if self._path and self._path.exists():
            self._load()

    # ------------------------------------------------------------------ #
    def lookup(self, host: str) -> str:
        """Return 'bad', 'good', or 'unknown' for a host."""
        h = host.lower().rstrip(".")
        if _match(h, self.known_bad):
            return "bad"
        if _match(h, self.known_good):
            return "good"
        entry = self._cache.get(h)
        if entry:
            status, expiry = entry
            if self._clock() < expiry:
                return status
            del self._cache[h]
        return "unknown"

    def learn(self, host: str, status: str) -> None:
        """Record a runtime verdict ('good' or 'bad') with TTL and persist."""
        if status not in ("good", "bad"):
            raise ValueError(f"reputation status must be 'good' or 'bad', got {status!r}")
        self._cache[host.lower().rstrip(".")] = (status, self._clock() + self.ttl)
        if self._path:
            self._save()

    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text())
            now = self._clock()
            self._cache = {
                h: (s, exp) for h, (s, exp) in raw.items()
                if isinstance(s, str) and exp > now
            }
        except Exception:
            # A corrupt cache degrades to empty — reputation is
            # defense-in-depth, so losing the cache loses convenience,
            # never enforcement.
            self._cache = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._cache, indent=1, sort_keys=True))
        except Exception:
            pass  # persistence failure must not break the decision path
