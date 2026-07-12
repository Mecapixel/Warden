"""
warden/platform/bundle.py  (v7)

Shareable policy bundles — the marketplace format.

A bundle (.wpb) is a ZIP containing policy files plus a MANIFEST.json that
pins every member by SHA-256, and optionally a MANIFEST.sig: an Ed25519
detached signature over the canonical manifest bytes. The same idea as v1.5
tool-definition pinning, applied to policy distribution: what you install is
byte-for-byte what the author shipped, and if it isn't, installation fails
loudly before a single file lands.

Laws:

  UNSIGNED IS UNTRUSTED.  `install()` requires a verified signature unless
        the caller passes allow_unsigned=True explicitly — deny by default,
        opt IN to risk, never out of safety.
  VERIFY BEFORE EXTRACT.  Every member is hashed against the manifest and
        checked for path traversal BEFORE anything is written. One bad
        member aborts the whole install; there are no partial installs.
  MISSING CRYPTO FAILS LOUD.  Signing and signature verification need the
        optional `cryptography` package (`pip install warden-security[sign]`).
        If it is absent, signed operations raise SigningUnavailable — they
        never silently degrade to unsigned.

Every policy file in a bundle must parse and validate against the policy
engine at pack time; a marketplace that ships broken policies is worse than
no marketplace.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_NAME = "MANIFEST.json"
SIGNATURE_NAME = "MANIFEST.sig"
BUNDLE_SUFFIX = ".wpb"
_POLICY_SUFFIXES = {".yaml", ".yml"}


class BundleError(ValueError):
    """Any structural, hash, signature, or safety failure in a bundle."""


class SigningUnavailable(RuntimeError):
    """The optional `cryptography` package is required for signed operations."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey)
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except ImportError as e:
        raise SigningUnavailable(
            "signed bundle operations require the optional `cryptography` "
            "package: pip install 'warden-security[sign]'") from e


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(manifest: dict[str, Any]) -> bytes:
    """The exact bytes that are signed: sorted-key, compact JSON."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def _safe_member(name: str) -> str:
    """Reject absolute paths and traversal in bundle member names."""
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or name.startswith(("/", "\\")):
        raise BundleError(f"unsafe member path in bundle: {name!r}")
    return name


@dataclass
class VerifyReport:
    ok: bool
    signed: bool
    signature_valid: bool | None      # None when unsigned or no key supplied
    name: str
    version: str
    files: dict[str, str]             # member -> sha256
    problems: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# keygen
# --------------------------------------------------------------------------- #

def keygen(private_path: str | Path, public_path: str | Path) -> None:
    """Generate an Ed25519 keypair (PEM private, raw-base64 public)."""
    Ed25519PrivateKey, _, serialization = _require_crypto()
    key = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    Path(public_path).write_text(base64.b64encode(raw).decode() + "\n")


# --------------------------------------------------------------------------- #
# pack
# --------------------------------------------------------------------------- #

def pack(source_dir: str | Path, out_path: str | Path,
         name: str, version: str,
         description: str = "",
         private_key_path: str | Path | None = None) -> Path:
    """Build a bundle from every policy file under source_dir.

    Every policy file is validated with the real PolicyEngine before packing.
    If private_key_path is given, the manifest is signed (Ed25519).
    """
    from warden.policy.engine import PolicyEngine, PolicyValidationError

    src = Path(source_dir)
    members: dict[str, bytes] = {}
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.suffix.lower() in _POLICY_SUFFIXES:
            rel = _safe_member(str(p.relative_to(src)))
            try:
                PolicyEngine(str(p))
            except PolicyValidationError as e:
                raise BundleError(f"{rel}: policy failed validation: {e}") from e
            members[rel] = p.read_bytes()
    if not members:
        raise BundleError(f"no policy files (*.yaml, *.yml) found under {src}")

    manifest = {
        "format": "warden-policy-bundle/1",
        "name": name,
        "version": version,
        "description": description,
        "created": datetime.now(timezone.utc).isoformat(),
        "files": {rel: _sha256(data) for rel, data in members.items()},
    }

    signature: bytes | None = None
    if private_key_path is not None:
        Ed25519PrivateKey, _, serialization = _require_crypto()
        key = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=None)
        signature = key.sign(_canonical(manifest))

    out = Path(out_path)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))
        if signature is not None:
            z.writestr(SIGNATURE_NAME, base64.b64encode(signature).decode())
        for rel, data in members.items():
            z.writestr(rel, data)
    return out


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #

def verify(bundle_path: str | Path,
           public_key_path: str | Path | None = None) -> VerifyReport:
    """Verify structure, per-file hashes, and (if key given) the signature.

    Verification is read-only and complete: every problem found is reported,
    not just the first.
    """
    problems: list[str] = []
    with zipfile.ZipFile(Path(bundle_path)) as z:
        names = set(z.namelist())
        if MANIFEST_NAME not in names:
            raise BundleError(f"not a warden bundle: missing {MANIFEST_NAME}")
        manifest = json.loads(z.read(MANIFEST_NAME))
        if manifest.get("format") != "warden-policy-bundle/1":
            raise BundleError(f"unknown bundle format: {manifest.get('format')!r}")

        declared: dict[str, str] = dict(manifest.get("files", {}))
        for rel in declared:
            _safe_member(rel)

        actual_members = names - {MANIFEST_NAME, SIGNATURE_NAME}
        for rel in sorted(actual_members - set(declared)):
            problems.append(f"undeclared member present: {rel}")
        for rel in sorted(set(declared) - actual_members):
            problems.append(f"declared member missing: {rel}")
        for rel in sorted(set(declared) & actual_members):
            got = _sha256(z.read(rel))
            if got != declared[rel]:
                problems.append(
                    f"hash mismatch: {rel} manifest={declared[rel][:12]}… actual={got[:12]}…")

        signed = SIGNATURE_NAME in names
        signature_valid: bool | None = None
        if public_key_path is not None:
            if not signed:
                problems.append("signature required for verification but bundle is unsigned")
                signature_valid = False
            else:
                _, Ed25519PublicKey, _ser = _require_crypto()
                raw = base64.b64decode(Path(public_key_path).read_text().strip())
                pub = Ed25519PublicKey.from_public_bytes(raw)
                sig = base64.b64decode(z.read(SIGNATURE_NAME))
                try:
                    pub.verify(sig, _canonical(manifest))
                    signature_valid = True
                except Exception:
                    problems.append("signature INVALID: manifest was not signed by this key")
                    signature_valid = False

    return VerifyReport(
        ok=not problems,
        signed=signed,
        signature_valid=signature_valid,
        name=str(manifest.get("name", "")),
        version=str(manifest.get("version", "")),
        files=declared,
        problems=problems,
    )


# --------------------------------------------------------------------------- #
# install
# --------------------------------------------------------------------------- #

def install(bundle_path: str | Path, dest_dir: str | Path,
            public_key_path: str | Path | None = None,
            allow_unsigned: bool = False) -> list[Path]:
    """Verify, then extract policy files into dest_dir. All-or-nothing.

    Signature policy (deny by default):
      * public_key_path given  -> signature must verify against that key.
      * no key, bundle signed  -> refused: a signature you cannot check is a
                                  claim you cannot trust (pass a key).
      * no key, unsigned       -> refused unless allow_unsigned=True.
    """
    report = verify(bundle_path, public_key_path)
    if public_key_path is None:
        if report.signed:
            raise BundleError(
                "bundle is signed but no public key was supplied to check it; "
                "pass --key (installing on an unverified signature is refused)")
        if not allow_unsigned:
            raise BundleError(
                "bundle is unsigned; refusing to install without explicit "
                "--allow-unsigned (deny by default)")
    if not report.ok:
        raise BundleError("bundle failed verification:\n  " + "\n  ".join(report.problems))

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    staged: list[tuple[Path, bytes]] = []
    with zipfile.ZipFile(Path(bundle_path)) as z:
        for rel in report.files:
            target = (dest / _safe_member(rel)).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise BundleError(f"member escapes destination: {rel!r}")
            staged.append((target, z.read(rel)))
    written: list[Path] = []
    for target, data in staged:          # verify-everything happened above
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        written.append(target)
    return written
