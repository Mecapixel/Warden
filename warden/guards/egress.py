"""
warden/guards/egress.py

Egress host-matching primitives — the v1 allowlist that closed the
exfiltration half of the indirect-injection kill chain, now the shared
foundation of the full v3 network subsystem.

An injected instruction that successfully steers the agent still has to move
data OFF the machine; if the destination host is not allowlisted, the tool
call dies here. v1 shipped this check alone (exact-host and wildcard-suffix
matching on URL-bearing arguments); v3 built the rest of the battery around
it — per-tool scopes, scheme control, SSRF resolve-then-validate, DNS
pinning and sinkholing, reputation, rate limiting, the download guard, and
canary tripwires — all in warden/network/. The matching semantics defined
here are used verbatim by the allowlist, per-tool scopes, sinkhole list, and
reputation lists, so one implementation carries one meaning of "matches"
everywhere: an allowlist and a sinkhole that disagreed about wildcards would
be a vulnerability shaped like a convenience.

Deny-by-default applies: if egress checking is enabled and a URL's host
matches nothing in the allowlist, the call is denied.
"""

from urllib.parse import urlparse


class EgressViolation(Exception):
    """Raised when a URL's host is not in the egress allowlist."""
    def __init__(self, url: str, host: str):
        self.url = url
        self.host = host
        super().__init__(f"host {host!r} (from {url!r}) is not in the egress allowlist")


def extract_host(url: str) -> str | None:
    """Best-effort hostname from a URL-ish string. None if not URL-shaped."""
    try:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
        return parsed.hostname
    except ValueError:
        return None


def host_allowed(host: str, allowlist: list[str]) -> bool:
    """Exact match, or wildcard suffix: '*.example.com' allows any subdomain
    of example.com (but NOT example.com itself — list it separately if wanted;
    implicit parent grants are how allowlists quietly over-grant)."""
    host = host.lower().rstrip(".")
    for entry in allowlist:
        e = entry.lower().rstrip(".")
        if e.startswith("*."):
            if host.endswith(e[1:]) and host != e[2:]:
                return True
        elif host == e:
            return True
    return False


def check_url(url: str, allowlist: list[str]) -> None:
    """Raise EgressViolation if url's host is not allowlisted.
    A URL whose host cannot be parsed is treated as a violation (fail closed)."""
    host = extract_host(url)
    if host is None:
        raise EgressViolation(url, "(unparseable)")
    if not host_allowed(host, allowlist):
        raise EgressViolation(url, host)
