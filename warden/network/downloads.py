"""
warden/network/downloads.py  (v3)

Download guard — payload inspection for data returning from tools.

A tool response is untrusted bytes. Four things it must never be allowed to
smuggle to the agent's side of the boundary:

  DL-001  oversized payloads      — memory exhaustion / context flooding
  DL-002  executable content      — PE (MZ), ELF, Mach-O magic bytes; an
                                    agent has no business receiving a binary
  DL-003  zip bombs               — archives whose expansion ratio or total
                                    expanded size is weaponized
  DL-004  nested archives         — archive-in-archive beyond a shallow
                                    depth; the classic scanner-evasion wrapper

Inspection is bounded by construction: archive analysis reads MEMBER
METADATA (declared sizes) and recurses only into archive-typed members up to
the depth cap, never inflating the payload wholesale — an inspector that
must explode the bomb to detect the bomb has already lost. Encrypted archive
members are a violation too: content that hides from inspection does not get
to cross the boundary (fail closed, same principle as everywhere else).

Payloads arrive as text on the MCP transport, so the mediator hands this
module both the raw bytes and, when the text is plausibly base64, the
decoded form — a binary dressed as text must be judged by what it decodes to.
"""

import base64
import binascii
import io
import re
import zipfile
from dataclasses import dataclass

_EXEC_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable (64-bit)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable (little-endian)"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary / Java class"),
)

_ZIP_MAGIC = b"PK\x03\x04"
_B64_SHAPE = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}\s*$")


@dataclass
class PayloadViolation:
    rule: str      # DL-001..DL-004
    detail: str


def maybe_base64(text: str) -> bytes | None:
    """Strict decode if the text is plausibly a base64 payload, else None.

    Gated on length and character shape so ordinary prose is never
    misparsed; strict validation (validate=True) rejects near-misses.
    """
    stripped = text.strip()
    if len(stripped) < 64 or not _B64_SHAPE.match(stripped):
        return None
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) % 4 != 0:
        return None
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def _inspect_zip(data: bytes, cfg: dict, depth: int) -> list[PayloadViolation]:
    max_depth = int(cfg.get("max_archive_depth", 2))
    max_expanded = int(cfg.get("max_archive_expanded_bytes", 100 * 1024 * 1024))
    max_ratio = float(cfg.get("max_compression_ratio", 100.0))
    violations: list[PayloadViolation] = []

    if depth > max_depth:
        return [PayloadViolation(
            "DL-004", f"archive nesting exceeds depth {max_depth} (scanner-evasion wrapper)")]

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile:
        # Zip magic with an unreadable structure: content that defeats
        # inspection is refused, not waved through.
        return [PayloadViolation("DL-003", "zip magic present but archive is unreadable (fail closed)")]

    declared_total = sum(i.file_size for i in infos)
    compressed_total = max(1, sum(i.compress_size for i in infos))

    if declared_total > max_expanded:
        violations.append(PayloadViolation(
            "DL-003",
            f"archive declares {declared_total:,} bytes expanded (cap {max_expanded:,})"))
    ratio = declared_total / compressed_total
    if ratio > max_ratio:
        violations.append(PayloadViolation(
            "DL-003",
            f"compression ratio {ratio:,.0f}:1 exceeds cap {max_ratio:,.0f}:1 (zip bomb signature)"))
    if violations:
        return violations   # do not open members of a payload already condemned

    for info in infos:
        if info.flag_bits & 0x1:
            return [PayloadViolation(
                "DL-004", f"encrypted archive member {info.filename!r} cannot be inspected (fail closed)")]
        if info.filename.lower().endswith((".zip", ".jar", ".apk")) or _looks_zip(zf, info):
            # Bounded read of just this member for the nesting check.
            with zf.open(info) as member:
                inner = member.read(min(info.file_size, 4 * 1024 * 1024))
            violations.extend(_inspect_zip(inner, cfg, depth + 1))
            if violations:
                return violations
    return violations


def _looks_zip(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bool:
    try:
        with zf.open(info) as member:
            return member.read(4) == _ZIP_MAGIC
    except Exception:
        return False


def inspect_payload(data: bytes, cfg: dict | None = None) -> list[PayloadViolation]:
    """Run the full guard battery over a payload. Empty list means clean."""
    cfg = cfg or {}
    violations: list[PayloadViolation] = []

    max_bytes = int(cfg.get("max_bytes", 25 * 1024 * 1024))
    if len(data) > max_bytes:
        violations.append(PayloadViolation(
            "DL-001", f"payload is {len(data):,} bytes (cap {max_bytes:,})"))

    if cfg.get("block_executables", True):
        for magic, name in _EXEC_MAGICS:
            if data.startswith(magic):
                violations.append(PayloadViolation("DL-002", f"executable content detected: {name}"))
                break

    if data.startswith(_ZIP_MAGIC):
        violations.extend(_inspect_zip(data, cfg, depth=1))

    return violations


def inspect_text_payload(text: str, cfg: dict | None = None) -> list[PayloadViolation]:
    """Inspect a text-transported payload: raw bytes AND base64-decoded form."""
    violations = inspect_payload(text.encode("utf-8", errors="replace"), cfg)
    decoded = maybe_base64(text)
    if decoded is not None:
        for v in inspect_payload(decoded, cfg):
            violations.append(PayloadViolation(v.rule, f"(base64-decoded) {v.detail}"))
    return violations
