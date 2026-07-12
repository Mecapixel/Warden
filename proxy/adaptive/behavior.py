"""
proxy/adaptive/behavior.py  (v6)

Behavioral baseline — learn what an agent normally does, flag when it stops
behaving like itself.

Every layer before this one asks a per-call question: is THIS action allowed?
Behavioral learning asks a different one: does this action fit the pattern of
this agent's past behavior? A tool call can be individually permitted and
still be the first sign of a compromise — a research agent that has read
1,000 files and never once touched the network suddenly opening egress is
each-call-legal and profile-breaking at the same time.

Three honest limits, stated because an anomaly detector that oversells
itself is worse than none:

  IT LEARNS, SO IT CAN BE POISONED. A baseline built from observed behavior
  can be walked slowly toward badness (frog-boiling). So learning is GATED:
  only ALLOW/observed-benign outcomes feed the profile, a warm-up count is
  required before the profile judges anything, and a `frozen` profile stops
  learning entirely for agents under suspicion. The v3 reputation-cache
  precedence lesson: learned state never overrides a hard control.

  IT PRODUCES SIGNALS, NOT VERDICTS. A deviation is an ESCALATE hint at
  most — it raises risk and can route to a human, but it never DENIES on its
  own. Deviation is not guilt; the policy layer remains the control.

  IT IS EXPLAINABLE. Every anomaly names the dimension that broke and the
  baseline it broke against ("egress to a host class never seen in 1,000
  prior calls"), because "the model flagged it" is not something a reviewer
  can defend.
"""

import json
import math
from dataclasses import dataclass, field, asdict
from typing import Any


DEFAULT_WARMUP = 30            # calls before a profile is allowed to judge
DEFAULT_NOVELTY_Z = 3.0       # rate-of-novelty z-score that trips ANOM-003


@dataclass
class AgentProfile:
    """A running, JSON-serializable summary of one agent's behavior.

    Deliberately a summary, not a log: counts and sets, no per-call history,
    so it cannot become a shadow audit trail or a PII sink.
    """
    agent_id: str
    calls: int = 0
    tools: dict[str, int] = field(default_factory=dict)
    host_classes: dict[str, int] = field(default_factory=dict)  # e.g. "public","internal"
    verdicts: dict[str, int] = field(default_factory=dict)
    max_risk_seen: int = 0
    frozen: bool = False        # suspicion freeze: stop learning, keep judging

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, blob: str) -> "AgentProfile":
        return cls(**json.loads(blob))


@dataclass
class Anomaly:
    rule: str
    dimension: str
    detail: str
    severity: int          # risk POINTS contributed, never a verdict


class BehaviorBaseline:
    """Learns per-agent profiles; scores a call against its agent's profile.

    Rules:
      ANOM-001  unfamiliar tool — a tool this agent has never invoked
      ANOM-002  unfamiliar host class — egress to a class never seen
      ANOM-003  risk spike — risk far above this agent's historical ceiling
    """

    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.warmup = int(cfg.get("warmup_calls", DEFAULT_WARMUP))
        self.novel_tool_points = int(cfg.get("novel_tool_points", 25))
        self.novel_host_points = int(cfg.get("novel_host_points", 40))
        self.risk_spike_points = int(cfg.get("risk_spike_points", 30))
        self.risk_spike_margin = int(cfg.get("risk_spike_margin", 30))
        if self.warmup < 0:
            raise ValueError("behavior.warmup_calls cannot be negative")
        self._profiles: dict[str, AgentProfile] = {}

    # ------------------------------------------------------------------ #
    def profile(self, agent_id: str) -> AgentProfile:
        return self._profiles.setdefault(agent_id, AgentProfile(agent_id))

    def load_profile(self, profile: AgentProfile) -> None:
        self._profiles[profile.agent_id] = profile

    def freeze(self, agent_id: str) -> None:
        """Stop learning from this agent (it is under suspicion) but keep
        scoring it against the baseline it had BEFORE the suspicion."""
        self.profile(agent_id).frozen = True

    # ------------------------------------------------------------------ #
    def observe(self, agent_id: str, tool: str, verdict: str,
                risk: int, host_class: str | None = None) -> None:
        """Fold one OUTCOME into the profile. Learning is gated: a frozen
        profile learns nothing, and only non-DENY outcomes teach 'normal'
        (a denied call is not an example of good behavior to imitate)."""
        p = self.profile(agent_id)
        p.verdicts[verdict] = p.verdicts.get(verdict, 0) + 1
        if p.frozen or verdict == "DENY":
            return
        p.calls += 1
        p.tools[tool] = p.tools.get(tool, 0) + 1
        if host_class:
            p.host_classes[host_class] = p.host_classes.get(host_class, 0) + 1
        p.max_risk_seen = max(p.max_risk_seen, risk)

    # ------------------------------------------------------------------ #
    def score(self, agent_id: str, tool: str, risk: int,
              host_class: str | None = None) -> list[Anomaly]:
        """Judge a call against the agent's baseline. Empty during warm-up:
        a profile that has seen too little cannot honestly call anything
        anomalous, and a detector that fires on cold-start is noise."""
        p = self.profile(agent_id)
        if p.calls < self.warmup:
            return []

        out: list[Anomaly] = []
        if tool not in p.tools:
            out.append(Anomaly(
                "ANOM-001", "tool",
                f"agent {agent_id!r} invoked {tool!r} for the first time in "
                f"{p.calls} observed calls", self.novel_tool_points))

        if host_class and host_class not in p.host_classes:
            seen = sorted(p.host_classes) or ["(no egress ever)"]
            out.append(Anomaly(
                "ANOM-002", "host_class",
                f"agent {agent_id!r} reached host class {host_class!r}; prior "
                f"egress only ever touched {seen}", self.novel_host_points))

        if risk > p.max_risk_seen + self.risk_spike_margin:
            out.append(Anomaly(
                "ANOM-003", "risk",
                f"risk {risk} exceeds this agent's historical ceiling of "
                f"{p.max_risk_seen} by more than {self.risk_spike_margin} "
                f"points", self.risk_spike_points))
        return out

    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict[str, str]:
        """All profiles as JSON, for persistence alongside the audit db."""
        return {aid: p.to_json() for aid, p in self._profiles.items()}
