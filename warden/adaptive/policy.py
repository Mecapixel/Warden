"""
warden/adaptive/policy.py  (v6)

Three v6 controls that share one discipline: context can only ADD caution,
never remove it. A ratchet, exactly like v4 approvals — the adaptive layer
can tighten in response to context, but can never loosen below the static
policy floor, because a control that context can relax is a control an
attacker can talk their way past.

  ADAPTIVE POLICIES — the same rule enforced more strictly in a riskier
  context. "filesystem.write escalates normally, but DENIES outright while
  the session is quarantined" is one rule with context-dependent
  enforcement. The escalation is always toward MORE restriction; a context
  rule that tried to downgrade a DENY to ALLOW is refused at load (ADAPT-002).

  QUARANTINE — automatic isolation of a suspect tool or session. Once
  quarantined, everything from that principal is forced to at least
  ESCALATE (or DENY, per policy), the behavioral baseline for it FREEZES so
  the compromise cannot teach itself into "normal", and the trust graph
  scopes the blast radius. Quarantine is sticky: it persists until a human
  clears it, never expiring on its own (QUAR-001).

  INTENT VERIFICATION — does this action match the goal the session
  declared? An agent tasked "summarize the quarterly report" that calls
  network egress or filesystem delete is off-goal; the mismatch is an
  ESCALATE hint, never an autonomous DENY, because a stated goal is
  self-reported and the human is the right adjudicator of "that's not what I
  asked for" (INTENT-001).
"""

from dataclasses import dataclass, field

from warden.core.decision import Verdict

_SEVERITY = {"ALLOW": 0, "REDACT": 1, "ESCALATE": 2, "DENY": 3}
_BY_SEVERITY = {v: k for k, v in _SEVERITY.items()}


def _at_least(verdict: str, floor: str) -> str:
    """Return whichever of the two is MORE restrictive. The ratchet."""
    return _BY_SEVERITY[max(_SEVERITY[verdict], _SEVERITY[floor])]


# --------------------------------------------------------------------------- #
# Adaptive context rules
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ContextRule:
    when: str                 # context flag, e.g. "quarantined","off_goal"
    floor: str                # minimum verdict while that flag holds

    def __post_init__(self):
        if self.floor not in _SEVERITY:
            raise ValueError(f"ADAPT-002: unknown floor verdict {self.floor!r}")


class AdaptivePolicy:
    """Applies context floors on top of a base verdict. Tighten-only."""

    def __init__(self, rules: list[ContextRule] | None = None):
        self.rules = rules or []

    @classmethod
    def from_policy(cls, cfg: dict | None) -> "AdaptivePolicy":
        cfg = cfg or {}
        rules = []
        for entry in cfg.get("context_rules", []):
            rule = ContextRule(when=str(entry["when"]),
                               floor=str(entry["floor"]))
            # A context rule may only raise the floor; declaring ALLOW as a
            # floor is legal (it's a no-op), but the ENFORCEMENT below can
            # never lower a verdict, so there is no way to express "relax".
            rules.append(rule)
        return cls(rules)

    def apply(self, base_verdict: str, context: set[str]) -> tuple[str, str | None]:
        """Return (possibly-tightened verdict, rule id if changed)."""
        verdict, fired = base_verdict, None
        for rule in self.rules:
            if rule.when in context:
                tightened = _at_least(verdict, rule.floor)
                if _SEVERITY[tightened] > _SEVERITY[verdict]:
                    verdict, fired = tightened, "ADAPT-001"
        return verdict, fired


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #
@dataclass
class QuarantineRecord:
    principal: str            # "session:abc" or "tool:http_get"
    reason: str
    floor: str = "ESCALATE"   # everything from this principal is >= this


class Quarantine:
    """Sticky isolation. Persists until a human clears it — never self-expires.

    The stickiness IS the security property: a quarantine that timed out on
    its own would let a patient adversary simply wait it out.
    """

    def __init__(self):
        self._held: dict[str, QuarantineRecord] = {}

    def quarantine(self, principal: str, reason: str,
                   floor: str = "ESCALATE") -> None:
        if floor not in _SEVERITY:
            raise ValueError(f"quarantine floor {floor!r} is not a verdict")
        self._held[principal] = QuarantineRecord(principal, reason, floor)

    def is_quarantined(self, principal: str) -> bool:
        return principal in self._held

    def clear(self, principal: str, cleared_by: str) -> bool:
        """Human-only release. Records who cleared it; returns whether it was
        held (so the caller can audit an attempt to clear nothing)."""
        if not cleared_by:
            raise ValueError(
                "QUAR-001: quarantine can only be cleared by a named human — "
                "automatic release would let an adversary wait out isolation")
        return self._held.pop(principal, None) is not None

    def floor_for(self, *principals: str) -> tuple[str, str | None]:
        """The strictest quarantine floor across the given principals."""
        verdict, who = "ALLOW", None
        for p in principals:
            rec = self._held.get(p)
            if rec and _SEVERITY[rec.floor] > _SEVERITY[verdict]:
                verdict, who = rec.floor, p
        return verdict, ("QUAR-001" if who else None)


# --------------------------------------------------------------------------- #
# Intent verification
# --------------------------------------------------------------------------- #
# Coarse capability families a stated goal implies. Deliberately conservative:
# when in doubt the action is considered on-goal, because the cost of a false
# "off-goal" is nagging a human about legitimate work until they stop reading.
_GOAL_CAPABILITIES = {
    "read":     {"filesystem.read", "search", "fetch", "http_get", "list"},
    "summarize": {"filesystem.read", "search", "fetch", "http_get", "list"},
    "analyze":  {"filesystem.read", "search", "fetch", "http_get", "list"},
    "write":    {"filesystem.write", "filesystem.read"},
    "edit":     {"filesystem.write", "filesystem.read"},
    "send":     {"email.send", "message.send", "http_post"},
    "deploy":   {"http_post", "exec"},
}
# Actions that are off-goal for a purely read/summarize task — the canonical
# "you asked me to read but I'm now deleting / exfiltrating" catch.
_SENSITIVE_ACTIONS = {"filesystem.delete", "filesystem.write", "email.send",
                      "message.send", "http_post", "exec", "network.egress"}


class IntentVerifier:
    """Compares an action against the session's stated goal. ESCALATE hint
    only — never an autonomous deny."""

    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.points = int(cfg.get("off_goal_points", 35))

    def check(self, stated_goal: str | None, tool: str) -> tuple[bool, str]:
        """Return (off_goal, explanation)."""
        if not stated_goal:
            return False, "no stated goal to verify against"

        goal_words = {w.strip(".,:;").lower() for w in stated_goal.split()}
        implied: set[str] = set()
        for verb, caps in _GOAL_CAPABILITIES.items():
            if verb in goal_words:
                implied |= caps

        if not implied:
            return False, "stated goal implies no specific capability set"

        if tool in implied:
            return False, f"{tool!r} is consistent with the stated goal"

        if tool in _SENSITIVE_ACTIONS:
            return True, (
                f"action {tool!r} is a sensitive operation the stated goal "
                f"(\"{stated_goal}\") does not imply — off-goal, routing to a "
                f"human (INTENT-001)")
        return False, f"{tool!r} is not obviously off-goal"
