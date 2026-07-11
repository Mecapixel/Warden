"""
proxy/identity/capabilities.py  (v4)

Capability tokens — per-request, cryptographically bound, least-privilege
grants.

The tier system answers "may this TOOL run?"; capabilities answer the finer
question "may this tool do THIS to THAT, right now?" A capability names a
verb (`filesystem.read`, `filesystem.write`, `filesystem.delete`,
`network.egress`, `exec.run`) and a target pattern (a canonical path glob,
a hostname), and exists only as a signed token minted by a session's issuer.

Design rules:

  1. UNFORGEABLE. Tokens are HMAC-SHA256 signed with a per-session key that
     never leaves the issuer. Verification recomputes the signature over the
     canonical payload; one flipped byte anywhere fails it. There is no
     "parse the token and trust its fields" path.
  2. SCOPED. A token grants exactly one capability against one target
     pattern. `filesystem.read` does not imply `filesystem.write`;
     `/workspace/data/*` does not cover `/workspace/secrets`. Wildcards
     widen a grant only when the ISSUER minted them wide.
  3. BOUNDED IN TIME. Every token carries issued-at and TTL; verification
     is against an injectable clock, so expiry is testable to the second.
  4. SINGLE-USE BY DEFAULT. "Per request" means per request: a consumed
     nonce is refused on replay (CAP-002). Reusable grants exist
     (`single_use=False`) for session-lifetime capabilities, but the caller
     opts into that explicitly.
  5. REVOCABLE AT THE ROOT. Destroying the issuer (session close) discards
     the key; every outstanding token dies with it, verified or not.

Failure anywhere — malformed token, unknown version, bad base64, expired,
consumed, wrong scope — is a refusal with a reason, never an exception the
caller might forget to catch.
"""

import base64
import binascii
import fnmatch
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable

TOKEN_VERSION = "WCAP1"
DEFAULT_TTL_SECONDS = 3600

# The capability vocabulary. Policy may extend it, but the core verbs are
# fixed so tool specs and approval policies share one language.
CORE_CAPABILITIES = frozenset({
    "filesystem.read",
    "filesystem.write",
    "filesystem.delete",
    "network.egress",
    "exec.run",
})


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    capability: str | None = None
    target_pattern: str | None = None


def capability_matches(granted: str, required: str) -> bool:
    """Does a granted capability name cover a required one?

    Exact match, or a wildcard family grant: 'filesystem.*' covers
    'filesystem.read' but never the reverse — a specific grant cannot be
    stretched into its family.
    """
    g, r = granted.strip().lower(), required.strip().lower()
    if g == r:
        return True
    if g.endswith(".*"):
        return r.startswith(g[:-1]) and r != g[:-2]
    return False


def target_matches(pattern: str, target: str) -> bool:
    """Glob match of a grant's target pattern against a concrete target.

    Paths are compared case-sensitively in canonical form (the engine hands
    this function the CANONICALIZED path, so `..` games were already killed
    upstream); hostnames should be lowered by the caller. '*' alone grants
    any target — the issuer chose that width, verification just honors it.
    """
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(target, pattern)


class CapabilityIssuer:
    """Mints and verifies capability tokens for one session.

    The signing key is generated fresh at construction and is never
    serialized. `revoke_all()` (called by session destruction) wipes it —
    after that, every verification fails by construction.
    """

    def __init__(self, session_id: str,
                 clock: Callable[[], float] = time.time):
        self.session_id = session_id
        self._key: bytes | None = secrets.token_bytes(32)
        self._clock = clock
        self._consumed: set[str] = set()

    # ------------------------------------------------------------------ #
    def mint(self, capability: str, target_pattern: str = "*",
             ttl_seconds: int = DEFAULT_TTL_SECONDS,
             single_use: bool = True) -> str:
        """Create a signed token string: WCAP1.<b64url payload>.<hex sig>."""
        if self._key is None:
            raise RuntimeError("issuer has been revoked; no new grants")
        payload = {
            "v": TOKEN_VERSION,
            "sid": self.session_id,
            "cap": capability.strip().lower(),
            "tgt": target_pattern,
            "iat": self._clock(),
            "ttl": int(ttl_seconds),
            "once": bool(single_use),
            "nonce": secrets.token_hex(16),
        }
        body = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        sig = hmac.new(self._key, f"{TOKEN_VERSION}.{body}".encode(),
                       hashlib.sha256).hexdigest()
        return f"{TOKEN_VERSION}.{body}.{sig}"

    # ------------------------------------------------------------------ #
    def verify(self, token: str, required_capability: str,
               target: str) -> VerifyResult:
        """Full verification battery. Any failure is a refusal with a why."""
        if self._key is None:
            return VerifyResult(False, "issuer revoked — session is closed")

        parts = (token or "").split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            return VerifyResult(False, "malformed token or unknown token version")
        _ver, body, presented_sig = parts

        expected = hmac.new(self._key, f"{TOKEN_VERSION}.{body}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, presented_sig):
            return VerifyResult(False, "signature verification failed (forged or foreign token)")

        try:
            padded = body + "=" * (-len(body) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
        except (binascii.Error, ValueError):
            # Signed-but-unparseable should be impossible; refuse anyway.
            return VerifyResult(False, "token payload could not be decoded (fail closed)")

        if payload.get("sid") != self.session_id:
            return VerifyResult(False, "token was minted for a different session")

        age = self._clock() - float(payload.get("iat", 0))
        if age > float(payload.get("ttl", 0)):
            return VerifyResult(False, f"token expired ({age:.0f}s old, ttl {payload.get('ttl')}s)")
        if age < -1.0:
            return VerifyResult(False, "token issued in the future (clock tamper signature)")

        cap = str(payload.get("cap", ""))
        if not capability_matches(cap, required_capability):
            return VerifyResult(False,
                                f"token grants {cap!r}, request requires {required_capability!r}",
                                capability=cap)

        tgt = str(payload.get("tgt", ""))
        if not target_matches(tgt, target):
            return VerifyResult(False,
                                f"target {target!r} is outside the grant's scope {tgt!r}",
                                capability=cap, target_pattern=tgt)

        nonce = str(payload.get("nonce", ""))
        if payload.get("once", True):
            if nonce in self._consumed:
                return VerifyResult(False, "single-use token replayed (already consumed)")
            self._consumed.add(nonce)

        return VerifyResult(True, "grant verified", capability=cap, target_pattern=tgt)

    # ------------------------------------------------------------------ #
    def revoke_all(self) -> None:
        """Session close: the key dies, and every outstanding token with it."""
        self._key = None
        self._consumed.clear()


class CapabilitySet:
    """A session's held grants: capability -> list of live tokens.

    `covers(capability, target)` is the question the policy engine asks. It
    tries the session's tokens for that capability family and returns the
    first verified grant; a set with no matching verified token does not
    cover, full stop. Reusable (session-lifetime) grants live here;
    single-use tokens pass through `covers` exactly once by construction.
    """

    def __init__(self, issuer: CapabilityIssuer):
        self.issuer = issuer
        self._tokens: list[str] = []

    def grant(self, capability: str, target_pattern: str = "*",
              ttl_seconds: int = DEFAULT_TTL_SECONDS,
              single_use: bool = False) -> str:
        token = self.issuer.mint(capability, target_pattern,
                                 ttl_seconds=ttl_seconds, single_use=single_use)
        self._tokens.append(token)
        return token

    def covers(self, capability: str, target: str) -> VerifyResult:
        last = VerifyResult(False, f"no grant held for {capability!r}")
        for token in self._tokens:
            result = self.issuer.verify(token, capability, target)
            if result.ok:
                return result
            last = result
        return last
