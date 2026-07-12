"""
warden/inspect/redactor.py

Secret and PII detection/redaction, applied in BOTH directions: on arguments
travelling to a tool, and on data returning to the agent's context window.

v1 uses regex plus a Shannon-entropy check for high-entropy tokens (the shape
of most API keys). This is intentionally dependency-light so v1 runs anywhere.
The detector names here match the policy.yaml `redaction.detectors` list.

A later phase can swap in Microsoft Presidio for far richer PII coverage
without changing the interface: keep `scan(text) -> list[Finding]` and
`redact(text) -> (clean_text, findings)` stable and the rest of the system
does not care what powers them.
"""

import math
import re
from dataclasses import dataclass


@dataclass
class Finding:
    detector: str      # which detector fired
    match: str         # the raw matched substring (never logged in the clear)
    start: int
    end: int


# Regex detectors. Deliberately conservative to limit false positives in v1;
# tune against the synthetic corpus in tests/.
_PATTERNS = {
    "aws_keys": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_keys": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "credit_cards": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    # Common API-key prefixes (extend as needed).
    # sk- keys allow hyphenated segment prefixes (sk-proj-..., sk-ant-...):
    # the segment class must admit hyphens or the newer formats never match.
    "api_keys": re.compile(
        r"\b(?:sk-(?:[A-Za-z0-9]+-)*[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
    ),
}

_REDACTION_TOKEN = "[REDACTED:{detector}]"

# Detector classes. Credentials are block-class: an agent moving a live
# credential is itself a stop-the-call signal. PII detectors (emails, ssn,
# credit_cards) are redact/inform-class: legitimate work routinely mentions an
# email address, and hard-blocking it teaches users to disable the control.
CREDENTIAL_DETECTORS = {"aws_keys", "private_keys", "api_keys"}

# Tokens above this Shannon entropy and length are treated as probable secrets
# even when they match no named pattern (catches novel/opaque key formats).
_ENTROPY_THRESHOLD = 4.0
_ENTROPY_MIN_LEN = 24


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_valid(number: str) -> bool:
    """Reduce credit-card false positives by validating the Luhn checksum."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def scan(text: str, detectors: list[str] | None = None) -> list[Finding]:
    """Return all findings in text for the enabled detectors."""
    if not text:
        return []
    enabled = set(detectors) if detectors else set(_PATTERNS.keys())
    findings: list[Finding] = []

    for name, pattern in _PATTERNS.items():
        if name not in enabled:
            continue
        for m in pattern.finditer(text):
            if name == "credit_cards" and not _luhn_valid(m.group()):
                continue
            findings.append(Finding(name, m.group(), m.start(), m.end()))

    # Entropy sweep for opaque high-entropy tokens, if api_keys is enabled.
    # URL-shaped tokens are excluded: URLs are naturally long and high-entropy,
    # and denying every tool call that carries a link is a false-positive
    # factory. A secret embedded IN a URL is still caught by the named
    # pattern detectors above.
    if "api_keys" in enabled:
        # Whitespace lookarounds instead of \b: word boundaries clip trailing
        # '=' padding off base64 secrets (and leading punctuation), so the
        # Finding span would under-cover the token and redact() would leave
        # fragments of the secret behind.
        for m in re.finditer(r"(?<!\S)\S{%d,}(?!\S)" % _ENTROPY_MIN_LEN, text):
            tok = m.group()
            if "://" in tok:
                continue
            already = any(f.start <= m.start() < f.end for f in findings)
            if not already and _shannon_entropy(tok) >= _ENTROPY_THRESHOLD:
                findings.append(Finding("api_keys", tok, m.start(), m.end()))

    # v1.5.5: optional Presidio backend — opt-in, additive, never a
    # replacement. Regex + entropy findings above always stand; Presidio
    # contributes richer PII on top, deduped where spans overlap.
    if "presidio" in enabled:
        from warden.inspect import presidio_backend
        for f in presidio_backend.scan_presidio(text):
            overlapped = any(
                f.start < g.end and g.start < f.end for g in findings)
            if not overlapped:
                findings.append(f)

    return findings


def redact(text: str, detectors: list[str] | None = None) -> tuple[str, list[Finding]]:
    """Return (redacted_text, findings). Secrets are replaced by a labeled
    token so the agent sees that redaction happened without seeing the value."""
    findings = scan(text, detectors)
    if not findings:
        return text, []
    # Replace from the end so indices stay valid as we mutate the string.
    out = text
    for f in sorted(findings, key=lambda x: x.start, reverse=True):
        out = out[: f.start] + _REDACTION_TOKEN.format(detector=f.detector) + out[f.end :]
    return out, findings
