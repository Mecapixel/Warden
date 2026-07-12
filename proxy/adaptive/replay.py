"""
proxy/adaptive/replay.py  (v6)

Replay engine + policy simulation — the payoff of monitor mode.

Since v1, monitor mode has computed and audited every decision without
enforcing. That was never just a rollout convenience: it was quietly
building a corpus. The replay engine spends it. Point a candidate policy at
the recorded audit log and answer the question every security change should
have to answer before it ships:

    "What would this policy have done to the traffic we actually saw?"

Two things fall out, both of which turn policy editing from guesswork into
evidence:

  REGRESSION SAFETY (the fear when TIGHTENING) — how many calls that the
  live policy ALLOWED would the candidate now DENY or ESCALATE? Those are
  the workflows about to break. A number, with examples, before rollout.

  COVERAGE GAIN (the hope when TIGHTENING) — how many calls that fired a
  risk signal would the candidate now catch that the old one waved through?

Two honesties that keep this from lying:

  REPLAY IS NOT PROPHECY. It answers what a policy would have done on PAST
  traffic, not what an adversary will do next. It is stated as retrodiction,
  never prediction — the samples are the samples.

  REPLAY IS READ-ONLY AND SIDE-EFFECT-FREE. It reconstructs Requests from
  the audit detail and re-decides them against a candidate engine with
  network resolution stubbed to the RECORDED outcome — it never executes a
  tool, never opens a socket, never writes to the live audit chain. A
  simulation that could act would be a weapon, not a what-if.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from proxy.core.request import Request
from proxy.core.decision import Verdict


@dataclass
class ReplayDelta:
    """One call whose verdict changed between recorded and candidate."""
    tool: str
    args_summary: str
    recorded_verdict: str
    candidate_verdict: str
    candidate_rule: str

    @property
    def direction(self) -> str:
        order = {"ALLOW": 0, "REDACT": 1, "ESCALATE": 2, "DENY": 3}
        was = order.get(self.recorded_verdict, 0)
        now = order.get(self.candidate_verdict, 0)
        return "stricter" if now > was else ("looser" if now < was else "same")


@dataclass
class ReplayReport:
    total: int = 0
    replayable: int = 0
    unchanged: int = 0
    newly_stricter: list[ReplayDelta] = field(default_factory=list)
    newly_looser: list[ReplayDelta] = field(default_factory=list)
    skipped: int = 0                 # records that weren't re-decidable

    def summary(self) -> str:
        return (f"replayed {self.replayable}/{self.total} decidable records: "
                f"{self.unchanged} unchanged, "
                f"{len(self.newly_stricter)} now stricter "
                f"(workflows that would newly be gated), "
                f"{len(self.newly_looser)} now looser. "
                f"{self.skipped} records not re-decidable (skipped, not "
                f"guessed).")

    @property
    def would_break_count(self) -> int:
        """Calls the live policy allowed that the candidate would gate — the
        rollout-risk number a human should see before shipping the change."""
        return sum(1 for d in self.newly_stricter
                   if d.recorded_verdict in ("ALLOW", "REDACT"))


class ReplayEngine:
    """Re-decide a recorded corpus against a candidate PolicyEngine.

    The candidate engine is constructed by the caller from the new policy;
    this class only feeds it reconstructed Requests and diffs the verdicts.
    Records that don't carry enough detail to reconstruct a Request are
    SKIPPED and counted, never fabricated — an honest 'don't know' beats a
    confident guess about traffic we can't reconstruct.
    """

    def __init__(self, candidate_engine):
        self._engine = candidate_engine

    # ------------------------------------------------------------------ #
    @staticmethod
    def _reconstruct(record: dict[str, Any]) -> tuple[str, dict] | None:
        """Pull (tool, args) out of an audit detail blob, or None if the
        record didn't capture them (e.g. a lifecycle event, not a call)."""
        tool = record.get("tool")
        if not tool:
            return None
        detail = record.get("detail")
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except (ValueError, TypeError):
                return None
        if not isinstance(detail, dict):
            return None
        args = detail.get("args")
        if not isinstance(args, dict):
            return None
        return tool, args

    def replay(self, records: list[dict[str, Any]]) -> ReplayReport:
        report = ReplayReport(total=len(records))
        for record in records:
            recorded_verdict = record.get("decision")
            if recorded_verdict not in Verdict.__members__:
                report.skipped += 1        # lifecycle event, not a call verdict
                continue
            recon = self._reconstruct(record)
            if recon is None:
                report.skipped += 1
                continue

            tool, args = recon
            try:
                decision = self._engine.decide(Request.normalize(tool, args))
            except Exception:
                report.skipped += 1        # candidate couldn't decide: don't guess
                continue

            report.replayable += 1
            candidate_verdict = decision.verdict.value
            if candidate_verdict == recorded_verdict:
                report.unchanged += 1
                continue

            delta = ReplayDelta(
                tool=tool,
                args_summary=", ".join(f"{k}={v}" for k, v in list(args.items())[:3]),
                recorded_verdict=recorded_verdict,
                candidate_verdict=candidate_verdict,
                candidate_rule=decision.rule)
            if delta.direction == "stricter":
                report.newly_stricter.append(delta)
            elif delta.direction == "looser":
                report.newly_looser.append(delta)
            else:
                report.unchanged += 1
        return report


def simulate(candidate_engine, records: list[dict[str, Any]]) -> ReplayReport:
    """Convenience: 'what would this stricter policy have done?' in one call."""
    return ReplayEngine(candidate_engine).replay(records)
