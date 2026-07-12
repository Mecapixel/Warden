"""
warden/network/dnspin.py  (v3)

DNS resolve-then-validate with pinning and sinkholing.

Two attacks live here:

  DNS-BASED SSRF — an allowlisted hostname whose DNS answer is an internal
  address. Defense: resolve the host at check time and validate EVERY
  returned address against the forbidden classes (addrguard). One bad
  address in the answer set poisons the whole answer — a resolver that
  returns [1.2.3.4, 169.254.169.254] is not half safe.

  DNS REBINDING — the host resolves clean when Warden checks it, then the
  attacker flips the record to an internal address before the tool connects
  (TOCTOU). Warden is a proxy, not the socket owner, so it cannot pin the
  literal connect() the downstream tool makes; what it CAN do is pin every
  validated resolution and treat a public-to-forbidden flip on a later
  request as a confirmed rebinding signal (SSRF-002) rather than a generic
  violation. The residual TOCTOU window is documented in THREAT_MODEL.md —
  a security tool that overstates its guarantees is itself a vulnerability.

Ordinary CDN rotation (public IP -> different public IP) is expected and is
NOT flagged; every fresh answer is still class-validated, which is the
enforcement that matters.

The resolver is injectable so the entire subsystem is testable without
touching real DNS, and so a deployment can swap in a DoH or caching resolver.
Resolution failure fails CLOSED: no answer means no permission.
"""

import socket
import time
from typing import Callable

from warden.network.addrguard import check_ip

Resolver = Callable[[str], list[str]]


class ResolutionError(Exception):
    """The host could not be resolved. Callers must fail closed."""


def default_resolver(host: str) -> list[str]:
    """System resolver via getaddrinfo, both families, deduplicated."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as e:
        raise ResolutionError(f"DNS resolution failed for {host!r}: {e}") from e
    seen: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise ResolutionError(f"DNS resolution for {host!r} returned no addresses")
    return seen


def host_sinkholed(host: str, sinkhole: list[str]) -> bool:
    """Exact or wildcard-suffix match against the sinkhole list.

    Same semantics as the egress allowlist wildcards: '*.tracker.example'
    covers subdomains but not the bare parent (list it separately).
    """
    h = host.lower().rstrip(".")
    for entry in sinkhole or []:
        e = entry.lower().rstrip(".")
        if e.startswith("*."):
            if h.endswith(e[1:]) and h != e[2:]:
                return True
        elif h == e:
            return True
    return False


class DnsPinCache:
    """Per-process record of validated resolutions, for rebinding detection.

    pin(host, ips)         — record a fully validated answer set.
    saw_clean(host) -> bool — has this host EVER resolved fully clean?

    The cache never grants anything. Its only power is to upgrade the
    attribution of a violation: a host that was clean before and dirty now
    is a rebinding flip (SSRF-002), which is worth distinguishing in the
    audit trail from a host that was simply always internal (SSRF-001).
    Entries expire so a stale pin cannot mislabel forever.
    """

    def __init__(self, ttl_seconds: int = 3600, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl_seconds
        self._clock = clock
        self._pins: dict[str, tuple[frozenset[str], float]] = {}

    def pin(self, host: str, ips: list[str]) -> None:
        self._pins[host.lower()] = (frozenset(ips), self._clock())

    def saw_clean(self, host: str) -> bool:
        entry = self._pins.get(host.lower())
        if entry is None:
            return False
        ips, at = entry
        if self._clock() - at > self.ttl:
            del self._pins[host.lower()]
            return False
        return True


def resolve_and_validate(host: str, forbidden: set[str],
                         resolver: Resolver | None = None,
                         pins: DnsPinCache | None = None) -> tuple[list[str] | None, str | None, str | None]:
    """Resolve host and validate every address against forbidden classes.

    Returns (ips, violation_class, rule):
      clean answer      -> (ips, None, None) and the answer is pinned
      forbidden address -> (None, class, 'SSRF-002' if the host was
                            previously clean — a rebinding flip — else
                            'SSRF-001')
      resolution failed -> (None, 'unresolvable', 'SSRF-001')  [fail closed]
    """
    try:
        ips = resolver(host) if resolver else default_resolver(host)
    except ResolutionError:
        return None, "unresolvable", "SSRF-001"
    except Exception:
        # An unexpected resolver crash is still a fail-closed denial, never
        # a pass-through.
        return None, "unresolvable", "SSRF-001"

    for ip in ips:
        cls = check_ip(ip, forbidden)
        if cls:
            rebound = pins.saw_clean(host) if pins else False
            return None, cls, ("SSRF-002" if rebound else "SSRF-001")

    if pins is not None:
        pins.pin(host, ips)
    return ips, None, None
