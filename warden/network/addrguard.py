"""
warden/network/addrguard.py  (v3)

IP address classification — the core of SSRF defense.

The classic SSRF kill chain against an agent gateway: the allowlist admits a
hostname, but the hostname's DNS answer points somewhere internal — the cloud
metadata service (169.254.169.254 hands out IAM credentials on AWS/Azure/GCP),
a link-local or loopback service, or an RFC 1918 host behind the perimeter.
Host-level allowlisting cannot see this; only classifying the RESOLVED
ADDRESSES can.

This module is pure classification: given an IP (v4 or v6), name every class
it belongs to. Policy decides which classes are forbidden. Two hard rules:

  1. Cloud metadata endpoints are ALWAYS forbidden when SSRF checking is
     enabled — there is no legitimate reason for an agent tool call to touch
     an instance-credential service, and the blast radius (live cloud
     credentials) is total.
  2. IPv4-mapped IPv6 addresses (::ffff:10.0.0.1) are unwrapped before
     classification, so the v6 form of a private v4 address cannot slip past
     a v4-only check.
"""

import ipaddress

# Instance metadata services. 169.254.169.254 is AWS/Azure/GCP/OpenStack;
# fd00:ec2::254 is AWS IPv6; 100.100.100.200 is Alibaba Cloud;
# 192.0.0.192 is Oracle Cloud legacy. These are forbidden unconditionally
# whenever SSRF checking is on.
METADATA_ADDRESSES = frozenset({
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",
    "192.0.0.192",
})

# Hostnames that ARE the metadata service regardless of resolution.
METADATA_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
})


def classify(ip_text: str) -> set[str]:
    """Return every address class the IP belongs to.

    Classes: metadata, loopback, link_local, private, reserved, multicast,
    unspecified. Unparseable input classifies as {'invalid'} — callers treat
    invalid as a violation (fail closed), never as a pass.
    """
    try:
        addr = ipaddress.ip_address(ip_text.strip().lower())
    except ValueError:
        return {"invalid"}

    # Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so the mapped form inherits
    # the classification of the inner v4 address.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    classes: set[str] = set()
    if str(addr) in METADATA_ADDRESSES:
        classes.add("metadata")
    if addr.is_loopback:
        classes.add("loopback")
    if addr.is_link_local:
        classes.add("link_local")
    if addr.is_private and not (addr.is_loopback or addr.is_link_local):
        # ipaddress marks loopback/link-local as private too; keep the
        # classes distinct so policy can control them independently.
        classes.add("private")
    if addr.is_multicast:
        classes.add("multicast")
    if addr.is_unspecified:
        classes.add("unspecified")
    if addr.is_reserved:
        classes.add("reserved")
    return classes


def forbidden_classes(cfg: dict) -> set[str]:
    """Translate the policy's ssrf config into the set of forbidden classes.

    'metadata', 'invalid', 'multicast', and 'unspecified' are always
    forbidden when SSRF checking is enabled — none has a legitimate agent
    use. loopback / link_local / private are policy-controlled and default
    to blocked (zero trust: the operator opts INTO internal reachability).
    """
    forbidden = {"metadata", "invalid", "multicast", "unspecified", "reserved"}
    if cfg.get("block_loopback", True):
        forbidden.add("loopback")
    if cfg.get("block_link_local", True):
        forbidden.add("link_local")
    if cfg.get("block_private", True):
        forbidden.add("private")
    return forbidden


def check_ip(ip_text: str, forbidden: set[str]) -> str | None:
    """Return the name of the first forbidden class the IP falls in, or None."""
    hit = classify(ip_text) & forbidden
    if hit:
        # Deterministic attribution: metadata outranks everything.
        for name in ("metadata", "invalid", "loopback", "link_local",
                     "private", "reserved", "multicast", "unspecified"):
            if name in hit:
                return name
        return sorted(hit)[0]
    return None
