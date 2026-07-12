"""
tests/test_v3_network_security.py

v3 — Network Security. Full control of outbound communication: the ordered
NetworkGuard battery (scheme, sinkhole, allowlist, per-tool scope, reputation,
SSRF resolve-then-validate), DNS pinning with rebinding attribution, the
download guard, the HTTP inspector, rate limiting, and canary tokens.

Every resolver is injected and every payload is synthetic — the whole suite
runs with zero real network I/O, by construction. Fail-closed behavior is
asserted at every boundary, because a security subsystem is defined by what
it does when its inputs are hostile or broken.
"""

import io
import json
import struct
import zipfile

import pytest

from warden.core.request import Request
from warden.core.decision import Verdict
from warden.policy.engine import PolicyEngine
from warden.audit.log import AuditLog
from warden.runtime.mediator import Mediator
from warden.runtime.approval import ApprovalGate

from warden.network.addrguard import classify, forbidden_classes, check_ip
from warden.network.dnspin import (
    DnsPinCache, ResolutionError, host_sinkholed, resolve_and_validate)
from warden.network.guard import NetworkGuard
from warden.network.reputation import ReputationCache
from warden.network.ratelimit import TokenBucket, RateLimiter
from warden.network.canary import CanaryVault
from warden.network import downloads, httpguard


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
ALL_FORBIDDEN = forbidden_classes({})   # defaults: everything blocked


def fake_resolver(mapping):
    """Build an injectable resolver from {host: [ips]}. Missing host fails."""
    def _resolve(host):
        if host not in mapping:
            raise ResolutionError(f"no fake record for {host!r}")
        return list(mapping[host])
    return _resolve


def make_zip(members, compression=zipfile.ZIP_DEFLATED):
    """Build an in-memory zip from {name: bytes}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# addrguard — IP classification (the core of SSRF defense)
# ---------------------------------------------------------------------------
class TestAddrGuard:
    def test_metadata_addresses_classified(self):
        for ip in ("169.254.169.254", "fd00:ec2::254",
                   "100.100.100.200", "192.0.0.192"):
            assert "metadata" in classify(ip), ip

    def test_ipv4_mapped_ipv6_unwrapped(self):
        # The v6 dress of a private v4 address must inherit its classification.
        assert "private" in classify("::ffff:10.0.0.1")
        assert "loopback" in classify("::ffff:127.0.0.1")

    def test_classes_are_distinct(self):
        assert classify("127.0.0.1") & {"loopback"} and "private" not in classify("127.0.0.1")
        assert classify("169.254.10.10") & {"link_local"} and "private" not in classify("169.254.10.10")
        assert "private" in classify("192.168.1.5")

    def test_invalid_input_fails_closed(self):
        assert classify("not-an-ip") == {"invalid"}
        assert check_ip("not-an-ip", ALL_FORBIDDEN) == "invalid"

    def test_public_address_is_clean(self):
        assert check_ip("93.184.216.34", ALL_FORBIDDEN) is None

    def test_metadata_always_forbidden_even_when_operator_opts_out(self):
        permissive = forbidden_classes(
            {"block_private": False, "block_loopback": False, "block_link_local": False})
        assert "metadata" in permissive
        assert "invalid" in permissive
        assert check_ip("169.254.169.254", permissive) == "metadata"
        # ...while the opted-out classes really are permitted.
        assert check_ip("10.0.0.1", permissive) is None

    def test_metadata_outranks_link_local_in_attribution(self):
        # 169.254.169.254 is both link-local and metadata; the audit record
        # must name the scarier truth.
        assert check_ip("169.254.169.254", ALL_FORBIDDEN) == "metadata"


# ---------------------------------------------------------------------------
# dnspin — sinkholing, resolve-then-validate, rebinding attribution
# ---------------------------------------------------------------------------
class TestDnsPin:
    def test_sinkhole_wildcard_covers_subdomains_not_parent(self):
        sink = ["*.tracker.example", "exact.example"]
        assert host_sinkholed("a.tracker.example", sink)
        assert host_sinkholed("deep.a.tracker.example", sink)
        assert not host_sinkholed("tracker.example", sink)
        assert host_sinkholed("exact.example", sink)
        assert not host_sinkholed("clean.example", sink)

    def test_one_bad_address_poisons_the_answer(self):
        r = fake_resolver({"cdn.example": ["93.184.216.34", "169.254.169.254"]})
        ips, cls, rule = resolve_and_validate("cdn.example", ALL_FORBIDDEN, resolver=r)
        assert ips is None and cls == "metadata" and rule == "SSRF-001"

    def test_clean_answer_is_pinned(self):
        pins = DnsPinCache()
        r = fake_resolver({"good.example": ["93.184.216.34"]})
        ips, cls, rule = resolve_and_validate("good.example", ALL_FORBIDDEN,
                                              resolver=r, pins=pins)
        assert ips == ["93.184.216.34"] and cls is None and rule is None
        assert pins.saw_clean("good.example")

    def test_rebinding_flip_attributed_ssrf_002(self):
        pins = DnsPinCache()
        clean = fake_resolver({"flip.example": ["93.184.216.34"]})
        resolve_and_validate("flip.example", ALL_FORBIDDEN, resolver=clean, pins=pins)
        dirty = fake_resolver({"flip.example": ["10.0.0.5"]})
        _ips, cls, rule = resolve_and_validate("flip.example", ALL_FORBIDDEN,
                                               resolver=dirty, pins=pins)
        assert cls == "private" and rule == "SSRF-002"

    def test_always_internal_host_is_ssrf_001(self):
        pins = DnsPinCache()
        dirty = fake_resolver({"intra.example": ["10.0.0.5"]})
        _ips, cls, rule = resolve_and_validate("intra.example", ALL_FORBIDDEN,
                                               resolver=dirty, pins=pins)
        assert cls == "private" and rule == "SSRF-001"

    def test_cdn_rotation_public_to_public_not_flagged(self):
        pins = DnsPinCache()
        r1 = fake_resolver({"cdn.example": ["93.184.216.34"]})
        r2 = fake_resolver({"cdn.example": ["151.101.1.1"]})
        assert resolve_and_validate("cdn.example", ALL_FORBIDDEN, resolver=r1, pins=pins)[1] is None
        assert resolve_and_validate("cdn.example", ALL_FORBIDDEN, resolver=r2, pins=pins)[1] is None

    def test_resolution_failure_fails_closed(self):
        r = fake_resolver({})
        _ips, cls, rule = resolve_and_validate("ghost.example", ALL_FORBIDDEN, resolver=r)
        assert cls == "unresolvable" and rule == "SSRF-001"

    def test_resolver_crash_fails_closed(self):
        def crashing(_host):
            raise RuntimeError("resolver exploded")
        _ips, cls, rule = resolve_and_validate("boom.example", ALL_FORBIDDEN, resolver=crashing)
        assert cls == "unresolvable" and rule == "SSRF-001"

    def test_pin_expires_after_ttl(self):
        t = [0.0]
        pins = DnsPinCache(ttl_seconds=100, clock=lambda: t[0])
        pins.pin("stale.example", ["93.184.216.34"])
        assert pins.saw_clean("stale.example")
        t[0] = 101.0
        assert not pins.saw_clean("stale.example")
        # An expired pin means a later dirty answer is SSRF-001, not -002:
        # the cache may not mislabel forever on stale memory.
        dirty = fake_resolver({"stale.example": ["10.0.0.9"]})
        _ips, _cls, rule = resolve_and_validate("stale.example", ALL_FORBIDDEN,
                                                resolver=dirty, pins=pins)
        assert rule == "SSRF-001"


# ---------------------------------------------------------------------------
# NetworkGuard — the single ordered battery
# ---------------------------------------------------------------------------
NET_CFG = {
    "ssrf": {"enabled": True},
    "dns": {"sinkhole": ["*.evil.example", "sinkholed.example"]},
    "reputation": {"enabled": True, "unknown_action": "allow",
                   "known_good": ["api.example.com", "cdn.trusted.org"],
                   "known_bad": ["burned.trusted.org"]},
}
EGRESS_CFG = {
    "enabled": True,
    "allowed_hosts": ["api.example.com", "*.trusted.org", "sinkholed.example"],
    "allowed_schemes": ["https"],
}
PUBLIC = fake_resolver({
    "api.example.com": ["93.184.216.34"],
    "cdn.trusted.org": ["151.101.1.1"],
    "internal.trusted.org": ["10.10.10.10"],
    "unknown.trusted.org": ["8.8.8.8"],
})


@pytest.fixture
def guard():
    return NetworkGuard(EGRESS_CFG, NET_CFG, resolver=PUBLIC)


class TestNetworkGuardBattery:
    def test_clean_url_passes_full_battery(self, guard):
        assert guard.check_url("https://api.example.com/v1/data") is None

    def test_unparseable_url_fails_closed(self, guard):
        v = guard.check_url("::::garbage::::")
        assert v is not None and v.rule == "EGR-001"

    def test_disallowed_scheme_denied(self, guard):
        v = guard.check_url("ftp://api.example.com/file")
        assert v.rule == "EGR-003"

    def test_sinkhole_beats_allowlist(self, guard):
        # sinkholed.example is ON the allowlist — the conflict must resolve
        # to the safe answer.
        v = guard.check_url("https://sinkholed.example/x")
        assert v.rule == "DNS-001"

    def test_metadata_hostname_denied_by_name(self, guard):
        v = guard.check_url("https://metadata.google.internal/computeMetadata/v1/")
        assert v.rule == "DNS-001"

    def test_unlisted_host_denied(self, guard):
        v = guard.check_url("https://attacker.example/collect")
        assert v.rule == "EGR-001"

    def test_tool_scope_narrows(self, guard):
        # Passes the global list, but outside this tool's declared scope.
        v = guard.check_url("https://cdn.trusted.org/asset",
                            tool_scope=["api.example.com"])
        assert v.rule == "EGR-002"

    def test_tool_scope_cannot_widen(self, guard):
        # In the tool's scope but NOT on the global allowlist: scopes only
        # subtract, so the global wall still denies it first.
        v = guard.check_url("https://widen.attacker.example/x",
                            tool_scope=["widen.attacker.example"])
        assert v.rule == "EGR-001"

    def test_known_bad_denies_allowlisted_host(self, guard):
        v = guard.check_url("https://burned.trusted.org/api")
        assert v.rule == "REP-001"

    def test_unknown_action_escalate_hints_escalate(self):
        cfg = dict(NET_CFG)
        cfg["reputation"] = {**NET_CFG["reputation"], "unknown_action": "escalate"}
        g = NetworkGuard(EGRESS_CFG, cfg, resolver=PUBLIC)
        v = g.check_url("https://unknown.trusted.org/x")
        assert v.rule == "REP-002" and v.verdict_hint == "escalate"

    def test_unknown_action_deny_denies(self):
        cfg = dict(NET_CFG)
        cfg["reputation"] = {**NET_CFG["reputation"], "unknown_action": "deny"}
        g = NetworkGuard(EGRESS_CFG, cfg, resolver=PUBLIC)
        v = g.check_url("https://unknown.trusted.org/x")
        assert v.rule == "REP-002" and v.verdict_hint == "deny"

    def test_ssrf_on_resolved_internal_address(self, guard):
        v = guard.check_url("https://internal.trusted.org/admin")
        assert v.rule == "SSRF-001" and v.signal == "ssrf_violation"

    def test_ssrf_rebinding_attributed_through_guard(self):
        answers = {"api.example.com": [["93.184.216.34"], ["169.254.169.254"]]}
        calls = {"n": 0}
        def flipping(host):
            ips = answers[host][min(calls["n"], 1)]
            calls["n"] += 1
            return ips
        g = NetworkGuard(EGRESS_CFG, NET_CFG, resolver=flipping)
        assert g.check_url("https://api.example.com/a") is None
        v = g.check_url("https://api.example.com/b")
        assert v.rule == "SSRF-002"

    def test_literal_metadata_ip_denied(self):
        egress = {**EGRESS_CFG, "allowed_hosts": EGRESS_CFG["allowed_hosts"] + ["169.254.169.254", "[::1]", "::1"]}
        g = NetworkGuard(egress, NET_CFG, resolver=PUBLIC)
        v = g.check_url("https://169.254.169.254/latest/meta-data/")
        assert v is not None and v.rule == "SSRF-001"

    def test_unresolvable_host_fails_closed_through_guard(self):
        g = NetworkGuard(EGRESS_CFG, NET_CFG, resolver=fake_resolver({}))
        v = g.check_url("https://api.example.com/x")
        assert v.rule == "SSRF-001" and "fail closed" in v.reason

    def test_escalate_hint_never_masks_ssrf_deny(self):
        # THE composition-rule regression, at the guard level: a host that is
        # reputation-unknown (escalate) AND resolves to the metadata service
        # must come back as a hard SSRF deny, not a human-approval prompt.
        cfg = dict(NET_CFG)
        cfg["reputation"] = {"enabled": True, "unknown_action": "escalate",
                             "known_good": [], "known_bad": []}
        r = fake_resolver({"unknown.trusted.org": ["169.254.169.254"]})
        g = NetworkGuard(EGRESS_CFG, cfg, resolver=r)
        v = g.check_url("https://unknown.trusted.org/x")
        assert v.rule == "SSRF-001" and v.verdict_hint == "deny"

    def test_escalate_hint_survives_clean_battery(self):
        # ...and when the rest of the battery IS clean, the escalate hint is
        # exactly what comes back — held pending, not dropped.
        cfg = dict(NET_CFG)
        cfg["reputation"] = {"enabled": True, "unknown_action": "escalate",
                             "known_good": [], "known_bad": []}
        r = fake_resolver({"unknown.trusted.org": ["8.8.8.8"]})
        g = NetworkGuard(EGRESS_CFG, cfg, resolver=r)
        v = g.check_url("https://unknown.trusted.org/x")
        assert v.rule == "REP-002" and v.verdict_hint == "escalate"


# ---------------------------------------------------------------------------
# Engine integration — the battery drives real Decisions
# ---------------------------------------------------------------------------
@pytest.fixture
def net_engine(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp_path}'\n"
        "egress:\n"
        "  enabled: true\n"
        "  allowed_hosts: [api.example.com, '*.trusted.org']\n"
        "  allowed_schemes: [https]\n"
        "network:\n"
        "  ssrf: {enabled: true}\n"
        "  dns: {sinkhole: ['*.evil.example']}\n"
        "  reputation:\n"
        "    enabled: true\n"
        "    unknown_action: escalate\n"
        "    known_good: [api.example.com]\n"
        "    known_bad: [burned.trusted.org]\n"
        "tools:\n"
        "  http_get: {tier: auto, url_args: [url]}\n"
        "  fetch_scoped: {tier: auto, url_args: [url], egress_hosts: [api.example.com]}\n"
    )
    return PolicyEngine(str(p), resolver=PUBLIC)


class TestEngineIntegration:
    def test_clean_url_allows(self, net_engine):
        d = net_engine.decide(Request.normalize("http_get", {"url": "https://api.example.com/v1"}))
        assert d.verdict == Verdict.ALLOW

    def test_ssrf_denies_with_rule(self, net_engine):
        # internal.trusted.org is ALSO reputation-unknown under this policy
        # (unknown_action: escalate) — and the SSRF deny must win anyway.
        # Regression for the escalate-masks-deny ordering flaw found by this
        # suite on its first run: a cheap check's "ask a human" must never
        # outrank an expensive check's "this resolves to internal space."
        d = net_engine.decide(Request.normalize(
            "http_get", {"url": "https://internal.trusted.org/admin"}))
        assert d.verdict == Verdict.DENY and d.rule == "SSRF-001"
        assert any(c["signal"] == "ssrf_violation" for c in d.risk_contributions)

    def test_reputation_unknown_escalates(self, net_engine):
        d = net_engine.decide(Request.normalize(
            "http_get", {"url": "https://unknown.trusted.org/x"}))
        assert d.verdict == Verdict.ESCALATE and d.rule == "REP-002"

    def test_known_bad_denies_even_allowlisted(self, net_engine):
        d = net_engine.decide(Request.normalize(
            "http_get", {"url": "https://burned.trusted.org/x"}))
        assert d.verdict == Verdict.DENY and d.rule == "REP-001"

    def test_per_tool_scope_enforced(self, net_engine):
        # cdn.trusted.org passes the global list and is known to reputation?
        # No — it's unknown, but scope check fires FIRST, so the rule must be
        # EGR-002 (ordering is part of the contract).
        d = net_engine.decide(Request.normalize(
            "fetch_scoped", {"url": "https://cdn.trusted.org/asset"}))
        assert d.verdict == Verdict.DENY and d.rule == "EGR-002"

    def test_scheme_violation_via_engine(self, net_engine):
        d = net_engine.decide(Request.normalize(
            "http_get", {"url": "ftp://api.example.com/f"}))
        assert d.verdict == Verdict.DENY and d.rule == "EGR-003"


# ---------------------------------------------------------------------------
# httpguard — redirect chains and header checks
# ---------------------------------------------------------------------------
class TestHttpGuard:
    def _checker(self, guard):
        return lambda u: guard.check_url(u)

    def test_clean_chain_passes(self, guard):
        hops = ["https://api.example.com/a", "https://cdn.trusted.org/b"]
        assert httpguard.check_redirect_chain(hops, self._checker(guard)) is None

    def test_bad_middle_hop_caught_with_attribution(self, guard):
        hops = ["https://api.example.com/a",
                "https://attacker.example/steal",
                "https://api.example.com/b"]
        v = httpguard.check_redirect_chain(hops, self._checker(guard))
        assert v.rule == "HTTP-002" and "redirect hop 1" in v.detail

    def test_redirect_to_metadata_service_caught(self, guard):
        hops = ["https://api.example.com/a", "https://metadata.google.internal/v1"]
        v = httpguard.check_redirect_chain(hops, self._checker(guard))
        assert v.rule == "HTTP-002" and "DNS-001" in v.detail

    def test_hop_cap_enforced(self, guard):
        hops = ["https://api.example.com/r%d" % i for i in range(8)]
        v = httpguard.check_redirect_chain(hops, self._checker(guard), max_hops=5)
        assert v.rule == "HTTP-001"

    def test_content_length_over_cap_refused(self):
        v = httpguard.check_headers({"Content-Length": "999999999"},
                                    {"max_content_length": 1000})
        assert v.rule == "HTTP-003"

    def test_unparseable_content_length_fails_closed(self):
        v = httpguard.check_headers({"content-length": "lots"}, {})
        assert v.rule == "HTTP-003"

    def test_header_names_case_insensitive(self):
        v = httpguard.check_headers({"CONTENT-LENGTH": "10"},
                                    {"max_content_length": 1000})
        assert v is None

    def test_mime_allowlist_enforced(self):
        cfg = {"allowed_mime_types": ["application/json", "text/*"]}
        assert httpguard.check_headers({"Content-Type": "application/json; charset=utf-8"}, cfg) is None
        assert httpguard.check_headers({"Content-Type": "text/plain"}, cfg) is None
        v = httpguard.check_headers({"Content-Type": "application/octet-stream"}, cfg)
        assert v.rule == "HTTP-004"

    def test_missing_content_type_with_allowlist_fails_closed(self):
        v = httpguard.check_headers({}, {"allowed_mime_types": ["text/*"]})
        assert v.rule == "HTTP-004"


# ---------------------------------------------------------------------------
# downloads — payload inspection
# ---------------------------------------------------------------------------
class TestDownloadGuard:
    def test_oversize_payload_dl001(self):
        v = downloads.inspect_payload(b"A" * 2048, {"max_bytes": 1024})
        assert any(x.rule == "DL-001" for x in v)

    def test_executable_magics_dl002(self):
        for magic in (b"MZ\x90\x00", b"\x7fELF\x02", b"\xfe\xed\xfa\xcf",
                      b"\xca\xfe\xba\xbe"):
            v = downloads.inspect_payload(magic + b"\x00" * 64)
            assert any(x.rule == "DL-002" for x in v), magic

    def test_zip_bomb_ratio_dl003(self):
        bomb = make_zip({"zeros.bin": b"\x00" * 2_000_000})
        v = downloads.inspect_payload(bomb, {"max_compression_ratio": 100.0})
        assert any(x.rule == "DL-003" for x in v)

    def test_declared_expansion_cap_dl003(self):
        z = make_zip({"big.bin": b"\x00" * 200_000})
        v = downloads.inspect_payload(z, {"max_archive_expanded_bytes": 100_000,
                                          "max_compression_ratio": 1e9})
        assert any(x.rule == "DL-003" for x in v)

    def test_nested_archive_beyond_depth_dl004(self):
        inner = make_zip({"data.txt": b"hello world, plenty of text here"},
                         compression=zipfile.ZIP_STORED)
        mid = make_zip({"inner.zip": inner}, compression=zipfile.ZIP_STORED)
        outer = make_zip({"mid.zip": mid}, compression=zipfile.ZIP_STORED)
        v = downloads.inspect_payload(outer, {"max_archive_depth": 2,
                                              "max_compression_ratio": 1e9})
        assert any(x.rule == "DL-004" for x in v)

    def test_shallow_clean_archive_passes(self):
        z = make_zip({"notes.txt": b"ordinary text content, nothing to see"},
                     compression=zipfile.ZIP_STORED)
        assert downloads.inspect_payload(z, {"max_compression_ratio": 1e9}) == []

    def test_encrypted_member_refused_dl004(self):
        z = bytearray(make_zip({"secret.txt": b"hidden content here"},
                               compression=zipfile.ZIP_STORED))
        # Set the encryption bit (bit 0 of general-purpose flags) in both the
        # local file header (offset 6) and the central directory record —
        # a real encrypted member advertises itself exactly this way.
        struct.pack_into("<H", z, 6, struct.unpack_from("<H", z, 6)[0] | 0x1)
        cd = bytes(z).find(b"PK\x01\x02")
        struct.pack_into("<H", z, cd + 8, struct.unpack_from("<H", z, cd + 8)[0] | 0x1)
        v = downloads.inspect_payload(bytes(z), {"max_compression_ratio": 1e9})
        assert any(x.rule == "DL-004" and "encrypted" in x.detail for x in v)

    def test_corrupt_zip_fails_closed_dl003(self):
        v = downloads.inspect_payload(b"PK\x03\x04" + b"\xff" * 32)
        assert any(x.rule == "DL-003" for x in v)

    def test_base64_wrapped_executable_detected(self):
        import base64 as b64
        payload = b64.b64encode(b"MZ\x90\x00" + b"\x00" * 120).decode()
        v = downloads.inspect_text_payload(payload)
        assert any(x.rule == "DL-002" and "(base64-decoded)" in x.detail for x in v)

    def test_maybe_base64_rejects_prose_and_short_strings(self):
        assert downloads.maybe_base64("This is an ordinary sentence.") is None
        assert downloads.maybe_base64("QUJD") is None            # too short
        assert downloads.maybe_base64("!" * 100) is None         # bad alphabet

    def test_plain_text_response_is_clean(self):
        assert downloads.inspect_text_payload("The weather is sunny today.") == []


# ---------------------------------------------------------------------------
# ratelimit — token buckets, injected clock
# ---------------------------------------------------------------------------
class TestRateLimit:
    def test_bucket_exhausts_and_refills(self):
        t = [0.0]
        b = TokenBucket(capacity=3, refill_per_second=1, clock=lambda: t[0])
        assert all(b.try_acquire() for _ in range(3))
        assert not b.try_acquire()
        t[0] = 2.0
        assert b.try_acquire() and b.try_acquire() and not b.try_acquire()

    def test_refill_never_exceeds_capacity(self):
        t = [0.0]
        b = TokenBucket(capacity=2, refill_per_second=10, clock=lambda: t[0])
        t[0] = 100.0
        assert b.try_acquire() and b.try_acquire() and not b.try_acquire()

    def test_invalid_config_rejected(self):
        with pytest.raises(ValueError):
            TokenBucket(capacity=0, refill_per_second=1)

    def test_per_tool_bucket_starves_before_global(self):
        t = [0.0]
        rl = RateLimiter({
            "enabled": True,
            "global": {"capacity": 100, "refill_per_second": 0},
            "per_tool": {"http_get": {"capacity": 2, "refill_per_second": 0}},
        }, clock=lambda: t[0])
        assert rl.acquire("http_get")[0] and rl.acquire("http_get")[0]
        ok, why = rl.acquire("http_get")
        assert not ok and "per-tool" in why
        # A quiet tool is not starved by the noisy one.
        assert rl.acquire("read_file")[0]

    def test_global_ceiling_spans_tools(self):
        t = [0.0]
        rl = RateLimiter({"enabled": True,
                          "global": {"capacity": 3, "refill_per_second": 0}},
                         clock=lambda: t[0])
        assert all(rl.acquire(f"tool_{i}")[0] for i in range(3))
        ok, why = rl.acquire("tool_x")
        assert not ok and "global" in why

    def test_disabled_limiter_always_allows(self):
        rl = RateLimiter({"enabled": False})
        assert all(rl.acquire("anything")[0] for _ in range(1000))


# ---------------------------------------------------------------------------
# canary — the zero-false-positive tripwire
# ---------------------------------------------------------------------------
class TestCanary:
    def test_mint_and_scan(self, tmp_path):
        v = CanaryVault(str(tmp_path / "canaries.json"))
        token = v.mint("decoy:test")
        hits = v.scan(f"POST https://x.example/?d={token} HTTP/1.1")
        assert hits == [(token, "decoy:test")]
        assert v.scan("nothing suspicious here") == []

    def test_seed_workspace_plants_three_labeled_decoys(self, tmp_path):
        v = CanaryVault(str(tmp_path / "canaries.json"))
        written = v.seed_workspace(str(tmp_path / "ws"))
        assert len(written) == 3 and v.count == 3
        # Every decoy file physically contains a registered marker.
        for path in written:
            content = open(path).read()
            assert v.scan(content), path

    def test_partial_exfiltration_still_trips(self, tmp_path):
        # Grepping just the "AWS key" line from the .env decoy carries the
        # marker with it.
        v = CanaryVault(str(tmp_path / "canaries.json"))
        written = v.seed_workspace(str(tmp_path / "ws"))
        env = next(p for p in written if p.endswith(".env"))
        secret_line = [l for l in open(env) if "AWS_SECRET_ACCESS_KEY" in l][0]
        assert v.scan(secret_line)

    def test_persistence_across_sessions(self, tmp_path):
        store = str(tmp_path / "canaries.json")
        token = CanaryVault(store).mint("decoy:session1")
        # A fresh vault (next session) still recognizes yesterday's marker —
        # the patient adversary who stashes and exfiltrates later.
        v2 = CanaryVault(store)
        assert v2.scan(f"exfil {token} now") == [(token, "decoy:session1")]

    def test_corrupt_store_degrades_to_empty(self, tmp_path):
        store = tmp_path / "canaries.json"
        store.write_text("{not json")
        v = CanaryVault(str(store))
        assert v.count == 0 and v.scan("anything") == []


# ---------------------------------------------------------------------------
# reputation — precedence, TTL, persistence
# ---------------------------------------------------------------------------
class TestReputation:
    def test_known_bad_beats_known_good(self):
        rep = ReputationCache(known_good=["dual.example"], known_bad=["dual.example"])
        assert rep.lookup("dual.example") == "bad"

    def test_wildcard_lists(self):
        rep = ReputationCache(known_bad=["*.malware.example"])
        assert rep.lookup("c2.malware.example") == "bad"
        assert rep.lookup("malware.example") == "unknown"

    def test_learned_verdict_expires(self):
        t = [1000.0]
        rep = ReputationCache(ttl_seconds=60, clock=lambda: t[0])
        rep.learn("temp.example", "bad")
        assert rep.lookup("temp.example") == "bad"
        t[0] = 1061.0
        assert rep.lookup("temp.example") == "unknown"

    def test_static_lists_beat_cache(self):
        rep = ReputationCache(known_bad=["fixed.example"])
        rep.learn("fixed.example", "good")
        assert rep.lookup("fixed.example") == "bad"

    def test_persistence_round_trip(self, tmp_path):
        path = str(tmp_path / "rep.json")
        t = [0.0]
        ReputationCache(cache_path=path, ttl_seconds=9999, clock=lambda: t[0]).learn("seen.example", "bad")
        rep2 = ReputationCache(cache_path=path, ttl_seconds=9999, clock=lambda: t[0])
        assert rep2.lookup("seen.example") == "bad"

    def test_corrupt_cache_degrades_to_empty(self, tmp_path):
        path = tmp_path / "rep.json"
        path.write_text("]]] not json")
        rep = ReputationCache(cache_path=str(path))
        assert rep.lookup("whatever.example") == "unknown"

    def test_invalid_learn_status_rejected(self):
        with pytest.raises(ValueError):
            ReputationCache().learn("x.example", "meh")


# ---------------------------------------------------------------------------
# Mediator integration — the full v3 flow end to end
# ---------------------------------------------------------------------------
@pytest.fixture
def med(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\n"
        f"workspace_root: '{tmp_path}'\n"
        "mode: enforce\n"
        "egress:\n"
        "  enabled: true\n"
        "  allowed_hosts: [api.example.com, '*.trusted.org']\n"
        "  allowed_schemes: [https]\n"
        "network:\n"
        "  ssrf: {enabled: true}\n"
        "  rate_limit:\n"
        "    enabled: true\n"
        "    global: {capacity: 100, refill_per_second: 0}\n"
        "    per_tool:\n"
        "      http_get: {capacity: 2, refill_per_second: 0}\n"
        "  downloads: {enabled: true, max_compression_ratio: 100}\n"
        "  http: {max_redirect_hops: 3, max_content_length: 1000}\n"
        "tools:\n"
        "  http_get: {tier: auto, url_args: [url], download_guard: true}\n"
        "  read_file: {tier: auto, path_args: [path]}\n"
    )
    engine = PolicyEngine(str(p), resolver=PUBLIC)
    audit = AuditLog(str(tmp_path / "audit.db"))
    canary = CanaryVault(str(tmp_path / "canaries.json"))
    canary.seed_workspace(str(tmp_path / "ws"))
    m = Mediator(engine, audit,
                 approval=ApprovalGate(asker=lambda _p: "n"),
                 canary=canary)
    yield m, canary
    audit.close()

class TestMediatorV3:
    def test_canary_in_outbound_args_is_confirmed_exfil(self, med):
        m, canary = med
        token = next(iter(canary._tokens))
        out = m.mediate_call("http_get",
                             {"url": f"https://api.example.com/?d={token}"})
        assert not out.execute
        assert out.decision.rule == "CAN-001"
        assert out.decision.risk_score == 100

    def test_rate_limit_denies_with_rate_001(self, med):
        m, _ = med
        assert m.mediate_call("http_get", {"url": "https://api.example.com/1"}).execute
        assert m.mediate_call("http_get", {"url": "https://api.example.com/2"}).execute
        out = m.mediate_call("http_get", {"url": "https://api.example.com/3"})
        assert not out.execute and out.decision.rule == "RATE-001"

    def test_rate_limited_tool_does_not_starve_others(self, med):
        m, _ = med
        m.mediate_call("http_get", {"url": "https://api.example.com/1"})
        m.mediate_call("http_get", {"url": "https://api.example.com/2"})
        m.mediate_call("http_get", {"url": "https://api.example.com/3"})   # denied
        assert m.mediate_call("read_file", {"path": "notes.txt"}).execute

    def test_redirect_chain_bad_hop_refused_and_audited(self, med):
        m, _ = med
        ok, reason = m.mediate_redirects(
            "http_get",
            ["https://api.example.com/a", "https://attacker.example/x"])
        assert not ok and "redirect hop 1" in reason

    def test_redirect_hop_cap_from_policy(self, med):
        m, _ = med
        hops = [f"https://api.example.com/{i}" for i in range(6)]   # 5 hops > cap 3
        ok, reason = m.mediate_redirects("http_get", hops)
        assert not ok and "cap 3" in reason

    def test_clean_redirect_chain_permitted(self, med):
        m, _ = med
        ok, _ = m.mediate_redirects(
            "http_get", ["https://api.example.com/a", "https://cdn.trusted.org/b"])
        assert ok

    def test_oversize_content_length_header_withheld(self, med):
        m, _ = med
        text, notes = m.mediate_response("http_get", "irrelevant",
                                         headers={"Content-Length": "999999"})
        assert "[WARDEN]" in text and any("HTTP-003" in n for n in notes)

    def test_zip_bomb_response_withheld(self, med):
        m, _ = med
        bomb = make_zip({"zeros.bin": b"\x00" * 2_000_000})
        text, notes = m.mediate_response("http_get",
                                         bomb.decode("latin-1"))
        assert "[WARDEN]" in text and any("DL-003" in n for n in notes)

    def test_clean_response_passes_through(self, med):
        m, _ = med
        text, _ = m.mediate_response("http_get", "ordinary JSON response body")
        assert text == "ordinary JSON response body"


# ---------------------------------------------------------------------------
# Policy validation — bad network config is refused at load, not at runtime
# ---------------------------------------------------------------------------
class TestPolicyValidation:
    def _load(self, tmp_path, network_block):
        p = tmp_path / "policy.yaml"
        p.write_text(
            "version: 1\n"
            f"workspace_root: '{tmp_path}'\n"
            f"{network_block}"
            "tools:\n  read_file: {tier: auto}\n"
        )
        return PolicyEngine(str(p))

    def test_bad_unknown_action_rejected(self, tmp_path):
        from warden.policy.engine import PolicyValidationError
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "network:\n  reputation: {enabled: true, unknown_action: maybe}\n")

    def test_bad_rate_limit_numbers_rejected(self, tmp_path):
        from warden.policy.engine import PolicyValidationError
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path,
                       "network:\n  rate_limit:\n    enabled: true\n"
                       "    global: {capacity: -5, refill_per_second: 1}\n")

    def test_bad_sinkhole_type_rejected(self, tmp_path):
        from warden.policy.engine import PolicyValidationError
        with pytest.raises(PolicyValidationError):
            self._load(tmp_path, "network:\n  dns: {sinkhole: 'not-a-list'}\n")

    def test_valid_network_block_loads(self, tmp_path):
        eng = self._load(tmp_path,
                         "network:\n  ssrf: {enabled: true}\n"
                         "  dns: {sinkhole: ['*.bad.example']}\n")
        assert eng.network_guard.ssrf_enabled
