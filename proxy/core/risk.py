"""
proxy/core/risk.py

Risk scoring. Instead of a bare allow/deny, each security signal contributes a
weighted number of points to a cumulative risk score (0-100). The final score
maps to a decision band, and — critically — every point is traceable to a named
contributor with a plain-language reason, so a reviewer can always answer
"why this score?"

WHY WEIGHTED SCORING INSTEAD OF BINARY:
A single signal is rarely the whole story. A write to the workspace is fine; a
write to the workspace *containing a secret* is not. Scoring lets independent
signals accumulate into an explainable total.

DEFENSIBILITY OF THE WEIGHTS (this matters — do not treat these as arbitrary):
The weights below are ordered by blast radius, i.e. how irreversible and how
severe the worst outcome of that signal is.

  filesystem_escape (60) — reading/writing outside the workspace can leak
      credentials (/etc/passwd, SSH keys) or overwrite system files. Worst
      case is full-host compromise; a hard boundary violation with no
      legitimate reason to cross.

  shell_injection (60) — arbitrary command execution is equivalent in blast
      radius to filesystem escape; both mean "the agent can do anything."

  policy_deny_tier / unknown_tool / unregistered_tool / mission_violation /
  egress_violation (60)
      — every deny-by-default signal carries the deny-band weight, by design:
      the SCORE and the VERDICT must tell the same story. A hard denial that
      scored in the escalate band would contradict itself in front of an
      auditor, so any signal that alone forces DENY is weighted >= 60.

  secret_in_transit (25) — a credential moving through a tool call is serious
      (exfiltration risk) but is often recoverable/rotatable, so it sits below
      the "total compromise" tier.

  prompt_injection (15) — an injection *attempt* is a strong signal of intent
      but is not itself a completed breach; it is weighted to push a request
      toward review, not to condemn it alone.

  pii_in_transit (10) — personal data (emails, SSNs, card numbers) in tool
      arguments is flagged as risk and surfaced to the human at the tier
      gate, rather than hard-blocking legitimate work that mentions a
      person's email address. Credentials block; PII informs.

  output_leak (10) — sensitive data in a RESPONSE is a real concern but is
      caught and redacted before the agent sees it, so it contributes least.

DECISION BANDS:
    0-24    ALLOW      (no meaningful risk)
    25-59   ESCALATE   (a human should look before this proceeds)
    60-100  DENY       (a hard-boundary violation is present)

The bands are set so that any single hard-boundary signal alone forces DENY,
while softer signals must accumulate to trigger escalation.
"""

from dataclasses import dataclass, field


# Named risk contributors and their point weights. Documented above.
RISK_WEIGHTS = {
    "filesystem_escape": 60,
    "shell_injection": 60,
    "policy_deny_tier": 60,      # explicitly denied tool
    "unknown_tool": 60,          # deny-by-default expressed as risk
    "unregistered_tool": 60,     # tool not in the allowlist registry
    "mission_violation": 60,     # action outside the declared mission
    "egress_violation": 60,      # network destination outside the allowlist
    "schema_drift": 60,          # tool definition changed since approval (pin)
    "secret_in_transit": 25,
    "prompt_injection": 15,
    "pii_in_transit": 10,
    "output_leak": 10,
}

BAND_ALLOW_MAX = 24
BAND_ESCALATE_MAX = 59


@dataclass
class RiskContribution:
    """One signal's contribution to the total score."""
    signal: str        # key from RISK_WEIGHTS
    points: int
    reason: str        # plain-language explanation for the audit trail


@dataclass
class RiskAssessment:
    """The accumulated risk for one request."""
    contributions: list[RiskContribution] = field(default_factory=list)

    def add(self, signal: str, reason: str, points: int | None = None) -> None:
        pts = RISK_WEIGHTS.get(signal, 0) if points is None else points
        self.contributions.append(RiskContribution(signal, pts, reason))

    @property
    def score(self) -> int:
        return min(100, sum(c.points for c in self.contributions))

    @property
    def band(self) -> str:
        s = self.score
        if s <= BAND_ALLOW_MAX:
            return "allow"
        if s <= BAND_ESCALATE_MAX:
            return "escalate"
        return "deny"

    def top_reason(self) -> str:
        if not self.contributions:
            return "no risk signals"
        top = max(self.contributions, key=lambda c: c.points)
        return top.reason
