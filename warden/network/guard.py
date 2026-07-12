"""
warden/network/guard.py  (v3)

NetworkGuard — the single ordered battery every outbound URL faces.

One entry point, one order, no second path. The engine calls check_url();
the HTTP inspector re-calls it for every redirect hop. Ordering is by cost
and confidence, cheap-and-certain first:

    1. Parse + scheme          (EGR-003; unparseable fails closed as EGR-001)
    2. DNS sinkhole            (DNS-001 — operator said never, so never)
    3. Global allowlist        (EGR-001 — the v1 wall, unchanged semantics)
    4. Per-tool egress scope   (EGR-002 — scopes NARROW the global list;
                                a tool-scoped host must pass BOTH. Scopes can
                                only subtract, never add — otherwise any tool
                                spec could quietly widen the perimeter)
    5. Reputation              (REP-001 known-bad denies even an allowlisted
                                host; REP-002 unknown escalates or denies per
                                policy — on an allowlist-passing host this is
                                belt over the suspenders, and the operator
                                chooses whether the belt is on)
    6. SSRF resolve-validate   (SSRF-001/SSRF-002 — the expensive check runs
                                last, only for URLs that earned it)

The verdict_hint on a violation tells the engine whether the operator asked
for a hard DENY or a human-in-the-loop ESCALATE (only REP-002 can hint
escalate). The engine maps hints to Decisions; the guard never decides.

Composition rule: the most severe verdict wins. An escalate hint from a
cheap check is held pending until the full battery has run — it is returned
only if nothing later demands a hard deny. A "no reputation record, ask a
human" finding must never mask a "resolves to the cloud metadata service"
finding, or the human at the gate decides on the wrong information.

The resolver is injectable end-to-end, so the whole battery runs in tests
with zero real network I/O.
"""

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from warden.guards.egress import extract_host, host_allowed
from warden.network.addrguard import forbidden_classes, check_ip, METADATA_HOSTNAMES
from warden.network.dnspin import (
    Resolver, DnsPinCache, host_sinkholed, resolve_and_validate,
)
from warden.network.reputation import ReputationCache


@dataclass
class NetworkViolation:
    rule: str            # EGR-001/2/3, DNS-001, REP-001/2, SSRF-001/2
    signal: str          # risk signal name for the RiskAssessment
    reason: str          # plain-language why, for the human
    verdict_hint: str = "deny"   # 'deny' or 'escalate' (REP-002 only)


class NetworkGuard:
    def __init__(self, egress_cfg: dict | None, network_cfg: dict | None,
                 resolver: Resolver | None = None):
        self.egress_cfg = egress_cfg or {}
        self.network_cfg = network_cfg or {}
        self.resolver = resolver

        self.allowed_hosts = self.egress_cfg.get("allowed_hosts", []) or []
        self.allowed_schemes = [
            s.lower() for s in (self.egress_cfg.get("allowed_schemes") or ["https", "http"])
        ]

        ssrf_cfg = self.network_cfg.get("ssrf") or {}
        self.ssrf_enabled = bool(ssrf_cfg.get("enabled"))
        self.forbidden = forbidden_classes(ssrf_cfg)

        dns_cfg = self.network_cfg.get("dns") or {}
        self.sinkhole = dns_cfg.get("sinkhole", []) or []
        self.pins = DnsPinCache(int(dns_cfg.get("pin_ttl_seconds", 3600)))

        rep_cfg = self.network_cfg.get("reputation") or {}
        self.rep_enabled = bool(rep_cfg.get("enabled"))
        self.unknown_action = str(rep_cfg.get("unknown_action", "allow")).lower()
        self.reputation = ReputationCache(
            known_good=rep_cfg.get("known_good"),
            known_bad=rep_cfg.get("known_bad"),
            cache_path=rep_cfg.get("cache_path"),
            ttl_seconds=int(rep_cfg.get("ttl_seconds", 86400)),
        ) if self.rep_enabled else None

    # ------------------------------------------------------------------ #
    def check_url(self, url: str, tool_scope: list[str] | None = None) -> NetworkViolation | None:
        """Run the full ordered battery. None means the URL is clean."""

        # 1. Parse + scheme. Fail closed on anything unparseable.
        try:
            parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
        except ValueError:
            parsed = None
        host = extract_host(url)
        if parsed is None or host is None:
            return NetworkViolation(
                "EGR-001", "egress_violation",
                f"URL {url!r} could not be parsed to a hostname (fail closed)")
        if parsed.scheme and parsed.scheme.lower() not in self.allowed_schemes:
            return NetworkViolation(
                "EGR-003", "egress_violation",
                f"scheme {parsed.scheme!r} is not permitted "
                f"(allowed: {', '.join(self.allowed_schemes)})")

        host = host.lower().rstrip(".")

        # 2. Sinkhole — the operator's hard never-list, checked before the
        # allowlist so a configuration conflict resolves to the safe answer.
        if host_sinkholed(host, self.sinkhole) or host in METADATA_HOSTNAMES:
            return NetworkViolation(
                "DNS-001", "dns_sinkhole",
                f"host {host!r} is sinkholed by policy")

        # 3. Global allowlist — the v1 wall, semantics unchanged.
        if not host_allowed(host, self.allowed_hosts):
            return NetworkViolation(
                "EGR-001", "egress_violation",
                f"destination host {host!r} is not in the egress allowlist")

        # 4. Per-tool scope — narrows, never widens.
        if tool_scope is not None and not host_allowed(host, tool_scope):
            return NetworkViolation(
                "EGR-002", "egress_violation",
                f"host {host!r} passed the global allowlist but is outside "
                f"this tool's declared egress scope")

        # 5. Reputation — defense-in-depth over the allowlist.
        #
        # Composition rule: the most severe verdict wins. A hard verdict
        # (deny) returns immediately, but an ESCALATE hint is held PENDING
        # while the rest of the battery runs — otherwise a mild finding from
        # a cheap check ("no reputation record, ask a human") would mask a
        # severe finding from a later one ("resolves to the cloud metadata
        # service"), and the human at the approval gate would be deciding on
        # the wrong information. Escalate is only the answer when nothing
        # after it demands deny.
        pending: NetworkViolation | None = None
        if self.reputation is not None:
            status = self.reputation.lookup(host)
            if status == "bad":
                return NetworkViolation(
                    "REP-001", "reputation_bad",
                    f"host {host!r} is on the known-bad reputation list")
            if status == "unknown" and self.unknown_action in ("deny", "escalate"):
                violation = NetworkViolation(
                    "REP-002", "reputation_unknown",
                    f"host {host!r} has no reputation record and policy "
                    f"gates unknown hosts ({self.unknown_action})",
                    verdict_hint=self.unknown_action)
                if self.unknown_action == "deny":
                    return violation
                pending = violation

        # 6. SSRF — resolve-then-validate, the expensive check last.
        if self.ssrf_enabled:
            literal = self._as_literal_ip(host)
            if literal is not None:
                cls = check_ip(literal, self.forbidden)
                if cls:
                    return NetworkViolation(
                        "SSRF-001", "ssrf_violation",
                        f"URL targets a literal {cls} address ({literal})")
            else:
                _ips, cls, rule = resolve_and_validate(
                    host, self.forbidden, resolver=self.resolver, pins=self.pins)
                if cls:
                    if cls == "unresolvable":
                        reason = f"host {host!r} could not be resolved (fail closed)"
                    elif rule == "SSRF-002":
                        reason = (f"host {host!r} previously resolved to public "
                                  f"addresses but now resolves into the {cls} "
                                  f"class — DNS rebinding signature")
                    else:
                        reason = f"host {host!r} resolves to a {cls} address"
                    return NetworkViolation(rule, "ssrf_violation", reason)

        # Nothing after the escalate hint demanded a hard deny — NOW the
        # human-in-the-loop question is the right question.
        return pending

    # ------------------------------------------------------------------ #
    @staticmethod
    def _as_literal_ip(host: str) -> str | None:
        candidate = host.strip("[]")   # bracketed IPv6 literals in URLs
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None
