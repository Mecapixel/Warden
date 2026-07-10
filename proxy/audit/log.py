"""
proxy/audit/log.py

Tamper-evident audit log. Every decision Warden makes is appended here as a
hash-chained record: each entry includes the SHA-256 of the previous entry, so
altering or deleting any entry breaks the chain and is detectable.

INTEGRITY DESIGN: the entry hash is computed over the CANONICAL JSON of the
full record (sorted keys), not a delimiter-joined string. Delimiter joining is
ambiguous — a field value containing the delimiter can make two different
records serialize identically — and ambiguity is unacceptable in the one
component whose entire job is tamper evidence. Canonical JSON makes every
record's byte representation unique and reproducible.

Storage is SQLite for zero external dependencies in v1. Chain integrity does
not depend on the database being immutable; it depends on the hash links,
which is what makes after-the-fact tampering evident even if the file is
writable.

CONCURRENCY: a process-wide lock serializes appends so the prev-hash read and
the insert are atomic together. Sufficient for v1's single process; revisit
when the MCP transport introduces concurrent sessions.
"""

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


def _entry_hash(event_id: str, parent_event_id: str | None, ts: float, tool: str,
                decision: str, reason: str, detail_json: str, prev_hash: str) -> str:
    canonical = json.dumps(
        {
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "ts": ts,
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "detail": detail_json,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        # Durability settings for a tamper-evidence log: WAL survives reader
        # concurrency without blocking appends, and synchronous=FULL means a
        # crash mid-commit cannot silently lose the tail of the chain — an
        # audit log that can drop its newest entries on power loss undermines
        # the very property it exists to provide.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                   seq INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL,
                   parent_event_id TEXT,
                   ts REAL NOT NULL,
                   tool TEXT,
                   decision TEXT NOT NULL,
                   reason TEXT,
                   detail TEXT,
                   prev_hash TEXT NOT NULL,
                   entry_hash TEXT NOT NULL
               )"""
        )
        self._conn.commit()

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else _GENESIS

    def record(self, tool: str, decision: str, reason: str,
               detail: dict[str, Any] | None = None,
               parent_event_id: str | None = None) -> str:
        """Append one decision. Returns the immutable event id.

        Every entry carries an event_id (UUID) and an optional parent_event_id
        linking related events into a chain WITHIN the tamper-evident chain:
        e.g. a tool-call decision -> its human-approval event -> its output-
        inspection event. Both ids are inside the hashed payload, so event
        identity and lineage are as tamper-evident as the record itself."""
        detail_json = json.dumps(detail or {}, sort_keys=True, default=str)
        event_id = str(uuid.uuid4())
        with self._lock:
            ts = time.time()
            prev = self._last_hash()
            entry_hash = _entry_hash(event_id, parent_event_id, ts, tool,
                                     decision, reason, detail_json, prev)
            self._conn.execute(
                "INSERT INTO audit (event_id, parent_event_id, ts, tool, decision, reason, detail, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, parent_event_id, ts, tool, decision, reason, detail_json, prev, entry_hash),
            )
            self._conn.commit()
        return event_id

    def verify_chain(self) -> bool:
        """Recompute every link. Returns True iff the chain is intact."""
        return self.verify_chain_detail()["intact"]

    def verify_chain_detail(self) -> dict[str, Any]:
        """Full verification report: walks the chain, recomputes every hash,
        and reports where (if anywhere) it breaks. Detects tampering,
        reordering, and truncation-with-splice; used by `warden verify`."""
        prev = _GENESIS
        count = 0
        for row in self._conn.execute(
            "SELECT seq, event_id, parent_event_id, ts, tool, decision, reason, detail, prev_hash, entry_hash "
            "FROM audit ORDER BY seq ASC"
        ):
            seq, event_id, parent_event_id, ts, tool, decision, reason, detail_json, prev_hash, entry_hash = row
            if prev_hash != prev:
                return {"intact": False, "entries": count,
                        "broken_at_seq": seq, "problem": "prev-hash link mismatch (reorder/removal)"}
            if _entry_hash(event_id, parent_event_id, ts, tool, decision, reason,
                           detail_json, prev_hash) != entry_hash:
                return {"intact": False, "entries": count,
                        "broken_at_seq": seq, "problem": "entry hash mismatch (record altered)"}
            prev = entry_hash
            count += 1
        return {"intact": True, "entries": count, "broken_at_seq": None, "problem": None}

    def close(self):
        self._conn.close()
