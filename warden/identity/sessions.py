"""
warden/identity/sessions.py  (v4)

Secure sessions — a bounded life for a bounded trust.

Everything an agent run is allowed to touch, hold, or prove is scoped to a
session, and a session is built to END:

  WORKSPACE     each session gets its own directory under the sessions
                root. Two concurrent agent runs cannot see each other's
                files, and yesterday's run left nothing behind for today's
                to exfiltrate.
  CAPABILITIES  the session opens with exactly the grants its user's role
                declares (rbac.role_capabilities) — minted as signed tokens
                by a per-session issuer whose key exists only in memory.
  CANARIES      the workspace is seeded with v3 canary decoys at open, so
                the zero-false-positive tripwire is armed from the first
                tool call of the session, automatically.
  AUDIT         open and close are records on the main hash chain, carrying
                the session id; every mediated call inside the session
                carries the same id, so "everything session X did" is one
                indexed query over a tamper-evident log — the per-session
                chain is a filtered view of the global one, not a second
                log that could disagree with it.
  DESTRUCTION   close() deletes the workspace tree, revokes the capability
                issuer (killing every outstanding token), and writes the
                closing audit record with the call count. A destroyed
                session can neither mint nor verify — not as policy, but
                because the key no longer exists.

Fail-closed corollary: anything asked of a closed session — covers(),
mint — is refused. There is no "mostly closed."
"""

import secrets
import shutil
import time
from pathlib import Path
from typing import Callable

from warden.identity.capabilities import CapabilityIssuer, CapabilitySet, VerifyResult
from warden.identity.rbac import Rbac
from warden.network.canary import CanaryVault


class SecureSession:
    def __init__(self, user: str, root: str, rbac: Rbac | None = None,
                 canary: CanaryVault | None = None,
                 seed_canaries: bool = True,
                 clock: Callable[[], float] = time.time):
        self.session_id = f"S-{secrets.token_hex(8)}"
        self.user = user
        self.opened_at = clock()
        self.closed = False
        self.calls = 0
        self._clock = clock

        self.workspace = Path(root) / self.session_id
        self.workspace.mkdir(parents=True, exist_ok=False)

        self.issuer = CapabilityIssuer(self.session_id, clock=clock)
        self.capabilities = CapabilitySet(self.issuer)
        if rbac is not None:
            for grant in rbac.role_capabilities(user):
                self.capabilities.grant(grant["capability"], grant["target"])

        self.canary_paths: list[str] = []
        if canary is not None and seed_canaries:
            self.canary_paths = canary.seed_workspace(str(self.workspace))

    # ------------------------------------------------------------------ #
    def covers(self, capability: str, target: str) -> VerifyResult:
        if self.closed:
            return VerifyResult(False, "session is closed — no grants survive destruction")
        self.calls += 1
        return self.capabilities.covers(capability, target)

    def grant(self, capability: str, target_pattern: str = "*", **kw) -> str:
        if self.closed:
            raise RuntimeError("cannot grant on a closed session")
        return self.capabilities.grant(capability, target_pattern, **kw)

    # ------------------------------------------------------------------ #
    def destroy(self) -> dict:
        """Wipe the workspace, revoke every grant, return the closing summary.

        Destruction is idempotent and cannot half-succeed into a usable
        state: the issuer is revoked FIRST, so even if the filesystem wipe
        raised, no token would verify afterward.
        """
        if self.closed:
            return {"session_id": self.session_id, "already_closed": True}
        self.closed = True
        self.issuer.revoke_all()
        wipe_error = None
        try:
            shutil.rmtree(self.workspace, ignore_errors=False)
        except OSError as e:
            wipe_error = repr(e)
            shutil.rmtree(self.workspace, ignore_errors=True)
        return {
            "session_id": self.session_id,
            "user": self.user,
            "opened_at": self.opened_at,
            "closed_at": self._clock(),
            "calls": self.calls,
            "workspace_wiped": not self.workspace.exists(),
            "wipe_error": wipe_error,
        }


class SessionManager:
    """Opens and closes sessions, and writes both events to the audit chain."""

    def __init__(self, root: str, rbac: Rbac | None = None,
                 canary: CanaryVault | None = None, audit=None,
                 seed_canaries: bool = True):
        self.root = root
        self.rbac = rbac
        self.canary = canary
        self.audit = audit
        self.seed_canaries = seed_canaries
        self._open: dict[str, SecureSession] = {}

    def open(self, user: str) -> SecureSession:
        session = SecureSession(user, self.root, rbac=self.rbac,
                                canary=self.canary,
                                seed_canaries=self.seed_canaries)
        self._open[session.session_id] = session
        if self.audit is not None:
            session.open_event_id = self.audit.record(
                "session", "SESSION_OPEN",
                f"session {session.session_id} opened for user {user!r}",
                {"session_id": session.session_id, "user": user,
                 "grants": len(session.capabilities._tokens),
                 "canaries": len(session.canary_paths)})
        return session

    def close(self, session: SecureSession) -> dict:
        summary = session.destroy()
        self._open.pop(session.session_id, None)
        if self.audit is not None and not summary.get("already_closed"):
            self.audit.record(
                "session", "SESSION_CLOSE",
                f"session {session.session_id} destroyed "
                f"(workspace wiped: {summary['workspace_wiped']})",
                {k: v for k, v in summary.items() if k != "user"} | {"user": session.user},
                parent_event_id=getattr(session, "open_event_id", None))
        return summary

    def get(self, session_id: str) -> SecureSession | None:
        return self._open.get(session_id)

    def close_all(self) -> None:
        for session in list(self._open.values()):
            self.close(session)
