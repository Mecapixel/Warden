"""
warden/identity/memguard.py  (v4)

Memory integrity — encrypt, sign, hash, and version long-term agent memory.

An agent's long-term memory is an attack surface with a long fuse: poison a
stored "fact" today and the agent acts on it next week, long after the
injection that planted it scrolled out of every context window. Warden
treats the memory store the way it treats the audit log — as a record whose
integrity must be PROVABLE, not assumed:

  SIGNED      every record carries an HMAC-SHA256 over its canonical form,
              keyed by a store key that lives beside the store with owner-
              only permissions. Edit one character of a stored memory and
              verification names the record (MEM-001).
  CHAINED     every record carries the hash of its predecessor, so records
              cannot be reordered, deleted from the middle, or inserted
              without breaking the chain (MEM-001).
  VERSIONED   every write is a new version; nothing is updated in place.
              The full history of a key is retained and readable — "what
              did the agent believe last Tuesday" is an answerable
              forensic question.
  HEAD-PINNED a separate signed head file records the chain length and tip
              hash. Truncating the store to resurrect an older state — the
              rollback attack, technically a valid chain — is caught by
              comparing against the head (MEM-002).
  ENCRYPTED   optionally, record content is encrypted at rest (Fernet,
              from the `cryptography` package). Same contract as every
              optional dependency in Warden: enabling it in policy when
              the backend cannot load is a POLICY ERROR at startup, never
              a silent downgrade at runtime.

Reads verify before they return: `get()` on a tampered store raises
MemoryIntegrityError rather than handing the agent poisoned state. An
integrity failure is loud by design — quiet acceptance of a bad chain is
the vulnerability.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_GENESIS = "0" * 64


class MemoryIntegrityError(Exception):
    """The store failed verification. Callers must not use its contents."""


@dataclass
class IntegrityViolation:
    rule: str        # MEM-001 tamper/chain-break, MEM-002 rollback
    detail: str


def _canonical(record: dict) -> bytes:
    body = {k: record[k] for k in sorted(record) if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class MemoryVault:
    """Append-only, signed, hash-chained, versioned key/value memory."""

    def __init__(self, store_path: str, key_path: str | None = None,
                 encrypt: bool = False,
                 clock: Callable[[], float] = time.time):
        self._path = Path(store_path)
        self._head_path = self._path.with_suffix(self._path.suffix + ".head")
        self._key_path = Path(key_path) if key_path else self._path.with_suffix(".key")
        self._clock = clock
        self._key = self._load_or_create_key()
        self._fernet = self._build_fernet() if encrypt else None
        self.encrypt = encrypt
        self._records: list[dict] = []
        if self._path.exists():
            self._records = self._read_store()
            violations = self._verify(self._records)
            if violations:
                raise MemoryIntegrityError(
                    "; ".join(f"{v.rule}: {v.detail}" for v in violations))

    # ------------------------------------------------------------------ #
    # Key material
    # ------------------------------------------------------------------ #
    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists():
            return bytes.fromhex(self._key_path.read_text().strip())
        key = secrets.token_bytes(32)
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key_path.write_text(key.hex())
        try:
            os.chmod(self._key_path, 0o600)   # best effort; not POSIX everywhere
        except OSError:
            pass
        return key

    def _build_fernet(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:
            raise MemoryIntegrityError(
                "memory encryption is enabled but the 'cryptography' package "
                "is not installed — refusing to run with silently-weaker "
                "protection than the operator configured. "
                "Install it with 'pip install cryptography', or disable "
                "identity.memory.encrypt."
            ) from e
        # Derive a stable Fernet key from the store key; one secret on disk.
        digest = hashlib.sha256(b"warden-memvault-fernet" + self._key).digest()
        import base64
        return Fernet(base64.urlsafe_b64encode(digest))

    # ------------------------------------------------------------------ #
    # Write path
    # ------------------------------------------------------------------ #
    def put(self, key: str, content: str) -> int:
        """Append a new version for `key`. Returns the version number."""
        version = self._latest_version(key) + 1
        prev_hash = self._records[-1]["this_hash"] if self._records else _GENESIS

        stored = content
        if self._fernet is not None:
            stored = self._fernet.encrypt(content.encode()).decode()

        record = {
            "seq": len(self._records) + 1,
            "key": key,
            "version": version,
            "ts": self._clock(),
            "encrypted": self._fernet is not None,
            "content": stored,
            "prev_hash": prev_hash,
        }
        record["this_hash"] = hashlib.sha256(_canonical(record)).hexdigest()
        record["sig"] = hmac.new(self._key, _canonical(record),
                                 hashlib.sha256).hexdigest()
        self._records.append(record)
        self._write_store()
        self._write_head()
        return version

    # ------------------------------------------------------------------ #
    # Read path — verify, then answer
    # ------------------------------------------------------------------ #
    def get(self, key: str, version: int | None = None) -> str | None:
        """Latest (or specific) version of a key. Verifies the store first."""
        self.verify_or_raise()
        candidates = [r for r in self._records if r["key"] == key]
        if version is not None:
            candidates = [r for r in candidates if r["version"] == version]
        if not candidates:
            return None
        record = candidates[-1]
        content = record["content"]
        if record.get("encrypted"):
            if self._fernet is None:
                raise MemoryIntegrityError(
                    f"record {record['seq']} is encrypted but this vault was "
                    "opened without encryption enabled")
            content = self._fernet.decrypt(content.encode()).decode()
        return content

    def history(self, key: str) -> list[tuple[int, float]]:
        """[(version, timestamp)] — what did the agent believe, and when."""
        self.verify_or_raise()
        return [(r["version"], r["ts"]) for r in self._records if r["key"] == key]

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self) -> list[IntegrityViolation]:
        """Re-read the store from disk and run the full battery."""
        on_disk = self._read_store() if self._path.exists() else []
        return self._verify(on_disk)

    def verify_or_raise(self) -> None:
        violations = self.verify()
        if violations:
            raise MemoryIntegrityError(
                "; ".join(f"{v.rule}: {v.detail}" for v in violations))

    def _verify(self, records: list[dict]) -> list[IntegrityViolation]:
        violations: list[IntegrityViolation] = []
        prev = _GENESIS
        for i, record in enumerate(records, start=1):
            canon = _canonical(record)
            expected_sig = hmac.new(self._key, canon, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_sig, str(record.get("sig", ""))):
                violations.append(IntegrityViolation(
                    "MEM-001", f"record {i} (key {record.get('key')!r}) failed "
                               f"signature verification — content or metadata edited"))
                # A broken signature invalidates hash comparison too; keep
                # walking so ALL damage is reported, but re-anchor prev.
            if record.get("prev_hash") != prev:
                violations.append(IntegrityViolation(
                    "MEM-001", f"record {i} breaks the hash chain — reorder, "
                               f"insertion, or mid-store deletion"))
            this = dict(record)
            this.pop("sig", None)
            # this_hash is computed over the record BEFORE the hash field is
            # attached (see put()); recomputation must exclude it the same
            # way, or the check is self-referential and can never pass.
            this.pop("this_hash", None)
            recomputed = hashlib.sha256(_canonical(this)).hexdigest()
            if recomputed != record.get("this_hash"):
                violations.append(IntegrityViolation(
                    "MEM-001", f"record {i} hash does not match its contents"))
            prev = str(record.get("this_hash", ""))

        # Rollback: the head file remembers how long the chain was and what
        # its tip hash was. A shorter-but-internally-valid store is a
        # truncation attack, not a fresh start.
        head = self._read_head()
        if head is None:
            if records:
                # Every put() writes the head alongside the store; a store
                # with records but NO head is the signature of a rollback
                # that deleted the head to silence MEM-002. Deleting the
                # witness does not acquit the defendant (fail closed).
                violations.append(IntegrityViolation(
                    "MEM-002", f"store holds {len(records)} records but the "
                               f"signed head file is missing — head deletion "
                               f"is a rollback signature, not a fresh start"))
        else:
            if len(records) < head["count"]:
                violations.append(IntegrityViolation(
                    "MEM-002", f"store holds {len(records)} records but the "
                               f"signed head pins {head['count']} — rollback/"
                               f"truncation detected"))
            elif len(records) == head["count"] and records and \
                    records[-1].get("this_hash") != head["tip"]:
                violations.append(IntegrityViolation(
                    "MEM-002", "store length matches the head but the tip hash "
                               "differs — tail substitution detected"))
        return violations

    # ------------------------------------------------------------------ #
    # Storage plumbing
    # ------------------------------------------------------------------ #
    def _latest_version(self, key: str) -> int:
        versions = [r["version"] for r in self._records if r["key"] == key]
        return max(versions) if versions else 0

    def _read_store(self) -> list[dict]:
        try:
            raw = json.loads(self._path.read_text())
            return raw if isinstance(raw, list) else []
        except (ValueError, OSError):
            raise MemoryIntegrityError(
                "memory store exists but cannot be parsed — refusing to "
                "guess at agent state (fail closed)")

    def _write_store(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._records, indent=1))

    def _write_head(self) -> None:
        head = {"count": len(self._records),
                "tip": self._records[-1]["this_hash"] if self._records else _GENESIS}
        head["sig"] = hmac.new(self._key, _canonical(head),
                               hashlib.sha256).hexdigest()
        self._head_path.write_text(json.dumps(head))

    def _read_head(self) -> dict | None:
        if not self._head_path.exists():
            return None
        try:
            head = json.loads(self._head_path.read_text())
            expected = hmac.new(self._key, _canonical(head),
                                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(head.get("sig", ""))):
                # A forged head could pin a rolled-back state as legitimate.
                raise MemoryIntegrityError(
                    "head file failed signature verification — cannot trust "
                    "the pinned chain state (fail closed)")
            return {"count": int(head["count"]), "tip": str(head["tip"])}
        except MemoryIntegrityError:
            raise
        except (ValueError, OSError, KeyError):
            raise MemoryIntegrityError(
                "head file is unreadable — cannot verify rollback state (fail closed)")
