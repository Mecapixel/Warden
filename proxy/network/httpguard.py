"""
proxy/network/httpguard.py  (v3)

HTTP inspector — redirect chains, MIME types, content length.

The redirect is the allowlist's oldest enemy: the agent requests an
allowlisted URL, the server answers 302, and the Location header points
anywhere it likes — an unlisted host, the metadata service, a private
address. Checking only the first URL is checking nothing. The rule here is
simple and absolute: EVERY hop in a redirect chain is a fresh network
decision, run through the identical battery (allowlist, scope, sinkhole,
reputation, SSRF resolution) as the original URL, plus a hop-count cap so a
redirect loop cannot spin the gateway.

Header checks are the cheap early wall on the response side: a declared
Content-Length over the cap or a Content-Type outside the allowed set is
refused before any payload inspection spends a byte of work. Declared
headers can lie, of course — which is why the download guard (downloads.py)
re-measures the actual payload; the two layers are deliberate redundancy,
not duplication.

This module owns no sockets. It judges URLs and headers the transport
reports, through the same injectable check function the engine uses —
keeping it pure, testable, and impossible to bypass by "forgetting" to
wire a second enforcement path.
"""

from dataclasses import dataclass
from typing import Callable


@dataclass
class HttpViolation:
    rule: str      # HTTP-001 (hop cap), HTTP-002 (hop failed checks),
                   # HTTP-003 (content length), HTTP-004 (MIME type)
    detail: str


def check_redirect_chain(hops: list[str],
                         url_check: Callable[[str], object | None],
                         max_hops: int = 5) -> HttpViolation | None:
    """Validate a redirect chain. `hops` is every URL in order, the original
    request first. `url_check` is NetworkGuard.check_url (or equivalent):
    returns None for a clean URL, a violation object otherwise.

    Returns the FIRST violation found — evaluation stops at the first bad
    hop because nothing after a poisoned hop deserves trust.
    """
    if len(hops) - 1 > max_hops:
        return HttpViolation(
            "HTTP-001",
            f"redirect chain has {len(hops) - 1} hops (cap {max_hops}) — loop or laundering chain")
    for i, url in enumerate(hops):
        violation = url_check(url)
        if violation is not None:
            where = "original URL" if i == 0 else f"redirect hop {i}"
            rule = getattr(violation, "rule", "EGR-001")
            reason = getattr(violation, "reason", str(violation))
            return HttpViolation(
                "HTTP-002", f"{where} failed network checks ({rule}): {reason}")
    return None


def check_headers(headers: dict[str, str], cfg: dict | None = None) -> HttpViolation | None:
    """Validate response headers against policy. Header names are matched
    case-insensitively (HTTP headers are case-insensitive by spec)."""
    cfg = cfg or {}
    lowered = {k.lower(): v for k, v in (headers or {}).items()}

    max_len = int(cfg.get("max_content_length", 25 * 1024 * 1024))
    raw_len = lowered.get("content-length")
    if raw_len is not None:
        try:
            declared = int(str(raw_len).strip())
        except ValueError:
            return HttpViolation("HTTP-003", f"unparseable Content-Length {raw_len!r} (fail closed)")
        if declared > max_len:
            return HttpViolation(
                "HTTP-003", f"declared Content-Length {declared:,} exceeds cap {max_len:,}")

    allowed = cfg.get("allowed_mime_types")
    if allowed:
        ctype = (lowered.get("content-type") or "").split(";")[0].strip().lower()
        if not ctype:
            return HttpViolation("HTTP-004", "missing Content-Type with a MIME allowlist in force (fail closed)")
        ok = any(
            ctype == a.lower() or
            (a.endswith("/*") and ctype.startswith(a[:-1].lower()))
            for a in allowed
        )
        if not ok:
            return HttpViolation("HTTP-004", f"Content-Type {ctype!r} is not in the allowed MIME set")
    return None
