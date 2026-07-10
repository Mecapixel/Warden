"""
proxy/core/metrics.py

Security metrics. Warden tracks aggregate counts from the first request so that
at any moment it can answer "what has this gateway actually done?" — which is
what makes a demo land: "247 requests, 19 blocked, 4 filesystem escapes stopped,
2 secrets caught, average risk 11/100."

Deliberately in-memory and dependency-free for v1. A later phase can persist or
export these (OpenTelemetry) behind the same interface.
"""

from collections import Counter
from dataclasses import dataclass, field

from proxy.core.decision import Decision, Verdict


@dataclass
class SecurityMetrics:
    total_requests: int = 0
    verdicts: Counter = field(default_factory=Counter)          # ALLOW/DENY/ESCALATE/REDACT
    signals: Counter = field(default_factory=Counter)           # risk signal -> count
    rules_fired: Counter = field(default_factory=Counter)       # rule id -> count
    _risk_sum: int = 0

    def record(self, decision: Decision) -> None:
        self.total_requests += 1
        self.verdicts[decision.verdict.value] += 1
        self.rules_fired[decision.rule] += 1
        self._risk_sum += decision.risk_score
        for c in decision.risk_contributions:
            self.signals[c["signal"]] += 1

    @property
    def average_risk(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return round(self._risk_sum / self.total_requests, 1)

    @property
    def blocked(self) -> int:
        return self.verdicts.get(Verdict.DENY.value, 0)

    @property
    def held_for_review(self) -> int:
        return self.verdicts.get(Verdict.ESCALATE.value, 0)

    def summary(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "allowed": self.verdicts.get(Verdict.ALLOW.value, 0),
            "blocked": self.blocked,
            "held_for_review": self.held_for_review,
            "average_risk": self.average_risk,
            "filesystem_escapes": self.signals.get("filesystem_escape", 0),
            "secrets_caught": self.signals.get("secret_in_transit", 0),
            "prompt_attacks": self.signals.get("prompt_injection", 0),
            "mission_violations": self.signals.get("mission_violation", 0),
        }

    def render(self) -> str:
        s = self.summary()
        return (
            f"requests={s['total_requests']}  allowed={s['allowed']}  "
            f"blocked={s['blocked']}  held={s['held_for_review']}  "
            f"avg_risk={s['average_risk']}/100  "
            f"escapes={s['filesystem_escapes']}  secrets={s['secrets_caught']}  "
            f"prompt_attacks={s['prompt_attacks']}  mission_violations={s['mission_violations']}"
        )
