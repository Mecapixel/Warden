"""
proxy/core/decision.py

The rich Decision object — Warden's answer to "why?"

A binary True/False tells you nothing when you are debugging, demoing, or
defending an enforcement action to an auditor. Every Warden decision instead
carries the full explanation: the verdict, the specific policy rule that fired,
the risk score and its contributors, a plain-language reason, a recommended
fix, and the audit ID that ties it to the tamper-evident log.

Design rule: no number without its derivation. A score of 60 is never just
"60" — it is 60 because filesystem_escape contributed 60 points for a named,
logged reason. Explainability is not a reporting feature bolted on at the end;
it is the shape of the data from the moment a decision is made.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from proxy.core.risk import RiskAssessment


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


@dataclass
class Decision:
    verdict: Verdict
    rule: str                        # policy rule id that governed this, e.g. "FS-004"
    action: str                      # the tool/action, e.g. "filesystem.read"
    reason: str                      # plain-language why
    risk_score: int = 0
    risk_contributions: list[dict[str, Any]] = field(default_factory=list)
    target: str | None = None        # e.g. the resolved path
    recommended_fix: str | None = None
    safe_path: str | None = None     # canonicalized path when applicable
    path_rewrites: dict[str, str] = field(default_factory=dict)  # arg key -> canonical path; the transport MUST rewrite these before forwarding so the checked path and the executed path are the same string
    redactions: list[str] = field(default_factory=list)
    request_id: str | None = None
    audit_id: str | None = None      # filled in after the decision is logged

    @classmethod
    def from_risk(cls, verdict: Verdict, rule: str, action: str,
                  assessment: RiskAssessment, **kw) -> "Decision":
        """Build a Decision from a RiskAssessment, capturing every contributor
        so the explanation is complete and traceable."""
        return cls(
            verdict=verdict,
            rule=rule,
            action=action,
            reason=kw.pop("reason", assessment.top_reason()),
            risk_score=assessment.score,
            risk_contributions=[
                {"signal": c.signal, "points": c.points, "reason": c.reason}
                for c in assessment.contributions
            ],
            **kw,
        )

    def explain(self) -> str:
        """Human-readable explanation block. Used by the CLI and demos."""
        lines = [
            f"Decision: {self.verdict.value}",
            f"Rule:     {self.rule}",
            f"Action:   {self.action}",
        ]
        if self.target:
            lines.append(f"Target:   {self.target}")
        lines.append(f"Reason:   {self.reason}")
        lines.append(f"Risk:     {self.risk_score}/100")
        if self.risk_contributions:
            for c in self.risk_contributions:
                lines.append(f"            +{c['points']:>3}  {c['signal']} — {c['reason']}")
        if self.recommended_fix:
            lines.append(f"Fix:      {self.recommended_fix}")
        if self.audit_id:
            lines.append(f"Audit ID: {self.audit_id}")
        return "\n".join(lines)
