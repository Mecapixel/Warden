"""
warden/runtime/pinning.py

Tool-definition pinning — Warden's trust boundary extended from runtime
requests to the *identity and integrity of the tools themselves*.

The threat: an MCP server advertises a benign tool at approval time, then
swaps its definition later — adding an `upload_to` parameter, widening a
path, or introducing a `delete_everything` tool — after the human has already
said yes. This is the MCP "rug pull," and a firewall that only inspects
requests never sees it, because the request looks valid against a definition
that changed underneath it.

Defense: every tool definition a server advertises is reduced to a CANONICAL
form (key order, whitespace, and encoding made deterministic) and hashed with
SHA-256. The hash is compared against the pinned, approved hash in a
persistent registry:

    server advertises tool
            |
    canonicalize schema  -->  SHA-256
            |
    compare to pinned hash
          /            \\
        same            changed / unseen
          |                   |
       ALLOW            DENY + audit + reapproval required

The registry keeps a full VERSION HISTORY per tool, not just the current
snapshot: every hash ever seen, when, and its approval state. That turns a
snapshot comparison into an auditable record of a tool's evolution, in the
same spirit as the hash-chained decision log.

This module is pure and does its own persistence (SQLite, zero extra deps);
the transport calls it at connection time. No network, no policy I/O.
"""

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


def canonical_schema(tool_def: dict[str, Any]) -> str:
    """Reduce a tool definition to a deterministic canonical string.

    Two definitions that differ only in key order or whitespace produce the
    same canonical form (and thus the same hash); any change to names, types,
    parameters, required fields, or description changes it. We canonicalize the
    whole advertised definition — description included — because a changed
    description is itself a signal worth re-approving (it can carry injected
    instructions to the model).
    """
    return json.dumps(tool_def, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def schema_hash(tool_def: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_schema(tool_def).encode()).hexdigest()


class PinVerdict(str, Enum):
    APPROVED = "APPROVED"          # hash matches an approved pin
    UNSEEN = "UNSEEN"             # tool never registered before
    DRIFTED = "DRIFTED"          # tool known, but hash changed


@dataclass
class PinResult:
    tool: str
    verdict: PinVerdict
    current_hash: str
    pinned_hash: str | None       # the approved hash on file, if any
    version: int                  # how many distinct definitions seen for this tool
    allowed: bool                 # may this definition run without reapproval?
    reason: str


class ToolRegistry:
    """Persistent pinned-tool registry with full per-tool version history.

    Schema:
      tools     — the currently APPROVED pin per tool name (fast lookup)
      history   — every (tool, hash) ever seen, with timestamp + approval state
    """

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # The transport queries the registry from worker threads (mediation
        # runs via asyncio.to_thread) while tools/list pinning runs on the
        # loop thread, so the connection must be shareable and every access
        # serialized by the lock below.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS tools (
                   name TEXT PRIMARY KEY,
                   approved_hash TEXT NOT NULL,
                   version INTEGER NOT NULL,
                   canonical TEXT NOT NULL,
                   approved_at REAL NOT NULL,
                   approved_by TEXT
               )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS history (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL,
                   hash TEXT NOT NULL,
                   canonical TEXT NOT NULL,
                   first_seen REAL NOT NULL,
                   state TEXT NOT NULL          -- APPROVED | REJECTED | PENDING
               )"""
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    def _approved(self, tool: str) -> tuple[str, int] | None:
        row = self._conn.execute(
            "SELECT approved_hash, version FROM tools WHERE name = ?", (tool,)
        ).fetchone()
        return (row[0], row[1]) if row else None

    def _seen_before(self, tool: str, h: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM history WHERE name = ? AND hash = ? LIMIT 1", (tool, h)
        ).fetchone()
        return row is not None

    def _distinct_versions(self, tool: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT hash) FROM history WHERE name = ?", (tool,)
        ).fetchone()
        return row[0] if row else 0

    def is_approved(self, tool: str) -> bool:
        """True iff the tool currently has an APPROVED pinned definition.

        Used by the transport's call-time gate: with a registry configured,
        a tool with no approved pin may not run, whether or not the server
        ever advertised it (deny by default at the pinning layer)."""
        with self._lock:
            return self._approved(tool) is not None

    def check(self, tool_def: dict[str, Any]) -> PinResult:
        """Evaluate an advertised tool definition against the pinned registry.

        Records every newly-seen (tool, hash) into history as PENDING, so the
        evolution record is complete even for definitions that get denied.
        Does NOT auto-approve anything — approval is an explicit action
        (approve()), so first sight of any tool is deny-by-default.
        """
        tool = tool_def.get("name")
        if not isinstance(tool, str) or not tool:
            return PinResult("(unnamed)", PinVerdict.DRIFTED, "", None, 0, False,
                             "tool definition has no usable name")

        h = schema_hash(tool_def)
        canonical = canonical_schema(tool_def)
        with self._lock:
            return self._check_locked(tool, tool_def, h, canonical)

    def _check_locked(self, tool: str, tool_def: dict[str, Any],
                      h: str, canonical: str) -> PinResult:
        approved = self._approved(tool)

        if not self._seen_before(tool, h):
            self._conn.execute(
                "INSERT INTO history (name, hash, canonical, first_seen, state) "
                "VALUES (?, ?, ?, ?, ?)",
                (tool, h, canonical, time.time(), "PENDING"))
            self._conn.commit()

        version = self._distinct_versions(tool)

        if approved is None:
            return PinResult(tool, PinVerdict.UNSEEN, h, None, version, False,
                             f"tool {tool!r} has never been approved; approval required")

        pinned_hash, _ = approved
        if h == pinned_hash:
            return PinResult(tool, PinVerdict.APPROVED, h, pinned_hash, version, True,
                             f"tool {tool!r} matches its approved definition")

        return PinResult(tool, PinVerdict.DRIFTED, h, pinned_hash, version, False,
                         f"tool {tool!r} definition changed since approval "
                         f"(pinned {pinned_hash[:12]}..., now {h[:12]}...); reapproval required")

    def approve(self, tool_def: dict[str, Any], approved_by: str = "operator") -> PinResult:
        """Pin the current definition as the approved one for this tool.

        Marks the matching history row APPROVED and bumps the tool's version to
        the count of distinct definitions ever seen — so version is a true
        evolution counter, not just an increment.
        """
        tool = tool_def["name"]
        h = schema_hash(tool_def)
        canonical = canonical_schema(tool_def)
        now = time.time()

        with self._lock:
            return self._approve_locked(tool, h, canonical, now, approved_by)

    def _approve_locked(self, tool: str, h: str, canonical: str,
                        now: float, approved_by: str) -> PinResult:
        if not self._seen_before(tool, h):
            self._conn.execute(
                "INSERT INTO history (name, hash, canonical, first_seen, state) "
                "VALUES (?, ?, ?, ?, ?)", (tool, h, canonical, now, "APPROVED"))
        else:
            self._conn.execute(
                "UPDATE history SET state = 'APPROVED' WHERE name = ? AND hash = ?",
                (tool, h))

        version = self._distinct_versions(tool)
        self._conn.execute(
            "INSERT INTO tools (name, approved_hash, version, canonical, approved_at, approved_by) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET approved_hash=excluded.approved_hash, "
            "version=excluded.version, canonical=excluded.canonical, "
            "approved_at=excluded.approved_at, approved_by=excluded.approved_by",
            (tool, h, version, canonical, now, approved_by))
        self._conn.commit()
        return PinResult(tool, PinVerdict.APPROVED, h, h, version, True,
                         f"tool {tool!r} approved and pinned (version {version})")

    def reject(self, tool_def: dict[str, Any]) -> None:
        """Mark a seen definition REJECTED in history (does not affect the pin)."""
        tool = tool_def.get("name", "(unnamed)")
        h = schema_hash(tool_def)
        with self._lock:
            self._conn.execute(
                "UPDATE history SET state = 'REJECTED' WHERE name = ? AND hash = ?",
                (tool, h))
            self._conn.commit()

    def history(self, tool: str) -> list[dict[str, Any]]:
        """Full evolution record for a tool, oldest first."""
        with self._lock:
            return self._history_locked(tool)

    def _history_locked(self, tool: str) -> list[dict[str, Any]]:
        return [
            {"hash": r[0], "first_seen": r[1], "state": r[2]}
            for r in self._conn.execute(
                "SELECT hash, first_seen, state FROM history WHERE name = ? "
                "ORDER BY id ASC", (tool,))
        ]

    def pinned_tools(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._pinned_tools_locked()

    def _pinned_tools_locked(self) -> list[dict[str, Any]]:
        return [
            {"name": r[0], "approved_hash": r[1], "version": r[2],
             "approved_at": r[3], "approved_by": r[4]}
            for r in self._conn.execute(
                "SELECT name, approved_hash, version, approved_at, approved_by "
                "FROM tools ORDER BY name ASC")
        ]

    def close(self):
        self._conn.close()
