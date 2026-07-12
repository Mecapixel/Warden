"""
warden/runtime/approval.py  (v1 gate, generalized in v4)

Human approval — from a yes/no prompt to a governed control.

The v1 gate asked one human one question and failed closed on everything
else. v4 keeps that gate as the primitive and adds the governance around it:

  PER-CAPABILITY POLICIES   the operator declares WHEN approval is required
                            — `always` for a capability like
                            filesystem.delete, `risk>=N` to gate on the
                            accumulated risk score — and the engine forces
                            ESCALATE (rule APR-001) when a policy fires.
                            Policies only ADD approval requirements; nothing
                            here can downgrade a tier the operator set. The
                            approval layer narrows, never widens — same law
                            as egress scopes and agent scopes.

  APPROVAL HISTORY          approvals and rejections were already events on
                            the tamper-evident audit chain (v1); v4 makes
                            them a first-class query. ApprovalHistory reads
                            the chain — the same chain, not a second log
                            that could disagree with it — and the gate puts
                            a history line in the prompt, because "this
                            exact tool was rejected three times today" is
                            information an approver should have. Informed
                            approval, on both axes: what the action is, and
                            what humans said about it before.

  TIMEOUT / ESCALATION      the timeout is policy-configurable and still
                            resolves to DENY — silence never becomes
                            consent, at any layer. An escalation CHAIN of
                            askers handles absence: if the first approver is
                            unavailable or times out, the next is asked. An
                            explicit human "no" STOPS the chain — escalation
                            exists to find someone present, never to shop a
                            rejection around until someone says yes.

Three v1 properties remain non-negotiable: fail closed on every failure
mode; the human sees the full explainable Decision; every answer lands on
the audit chain, parent-linked to the decision that triggered it.
"""

import json
import threading
from dataclasses import dataclass
from typing import Callable

from warden.core.decision import Decision

DEFAULT_TIMEOUT_SECONDS = 120


# --------------------------------------------------------------------------- #
# Per-capability approval policies (v4)
# --------------------------------------------------------------------------- #
class ApprovalPolicyError(ValueError):
    """A policy entry could not be parsed. Raised at LOAD, not at runtime."""


@dataclass
class ApprovalRequirement:
    required: bool
    why: str | None = None


class ApprovalPolicies:
    """Parsed `identity.approval.policies` from policy.yaml.

    Entry shapes (key is a capability name or a tool name):
        filesystem.delete: always      # every use needs a human
        network.egress: "risk>=50"     # human above a risk score
        read_file: never               # explicit no-added-requirement

    `never` is deliberately inert relative to tiers: it records the
    operator's intent in policy but cannot cancel a `tier: escalate` — the
    approval layer only adds requirements.
    """

    def __init__(self, cfg: dict | None):
        self._always: set[str] = set()
        self._risk_at: dict[str, int] = {}
        for key, raw in (cfg or {}).items():
            rule = str(raw).strip().lower()
            name = str(key).strip().lower()
            if rule == "always":
                self._always.add(name)
            elif rule == "never":
                continue
            elif rule.startswith("risk>="):
                try:
                    self._risk_at[name] = int(rule[len("risk>="):])
                except ValueError:
                    raise ApprovalPolicyError(
                        f"identity.approval.policies.{key}: {raw!r} — "
                        f"risk threshold must be an integer (e.g. 'risk>=50')")
            else:
                raise ApprovalPolicyError(
                    f"identity.approval.policies.{key}: {raw!r} is not a "
                    f"valid rule (use 'always', 'never', or 'risk>=N')")

    def requirement(self, names: list[str], risk_score: int) -> ApprovalRequirement:
        """Do any of these names (capability, tool) demand approval now?"""
        for name in names:
            n = (name or "").strip().lower()
            if not n:
                continue
            if n in self._always:
                return ApprovalRequirement(
                    True, f"approval policy for {n!r} is 'always'")
            threshold = self._risk_at.get(n)
            if threshold is not None and risk_score >= threshold:
                return ApprovalRequirement(
                    True, f"approval policy for {n!r} requires a human at "
                          f"risk>={threshold} (score is {risk_score})")
        return ApprovalRequirement(False)


# --------------------------------------------------------------------------- #
# Approval history (v4) — a read-only view over the audit chain
# --------------------------------------------------------------------------- #
class ApprovalHistory:
    def __init__(self, audit_log):
        self._audit = audit_log

    def summary(self, tool: str | None = None,
                since_ts: float | None = None) -> dict:
        """Counts of APPROVED / REJECTED events, optionally per tool / window."""
        q = ("SELECT decision, COUNT(*) FROM audit "
             "WHERE decision IN ('APPROVED', 'REJECTED')")
        params: list = []
        if tool is not None:
            q += " AND tool = ?"
            params.append(tool)
        if since_ts is not None:
            q += " AND ts >= ?"
            params.append(since_ts)
        q += " GROUP BY decision"
        counts = {"APPROVED": 0, "REJECTED": 0}
        for decision, n in self._audit._conn.execute(q, params):
            counts[decision] = n
        return counts

    def recent(self, tool: str | None = None, limit: int = 5) -> list[dict]:
        q = ("SELECT ts, tool, decision, reason, detail FROM audit "
             "WHERE decision IN ('APPROVED', 'REJECTED')")
        params: list = []
        if tool is not None:
            q += " AND tool = ?"
            params.append(tool)
        q += " ORDER BY seq DESC LIMIT ?"
        params.append(limit)
        out = []
        for ts, t, decision, reason, detail_json in self._audit._conn.execute(q, params):
            try:
                detail = json.loads(detail_json)
            except ValueError:
                detail = {}
            out.append({"ts": ts, "tool": t, "decision": decision,
                        "reason": reason, "rule": detail.get("rule")})
        return out

    def prompt_line(self, tool: str) -> str:
        counts = self.summary(tool=tool)
        total = counts["APPROVED"] + counts["REJECTED"]
        if total == 0:
            return f"History for {tool!r}: no prior approval decisions."
        return (f"History for {tool!r}: {counts['APPROVED']} approved, "
                f"{counts['REJECTED']} rejected previously.")


# --------------------------------------------------------------------------- #
# The gate (v1 primitive, history-aware in v4)
# --------------------------------------------------------------------------- #
@dataclass
class ApprovalResult:
    approved: bool
    method: str      # "tty" | "callback" | "unavailable" | "timeout" | "error"
    detail: str


class ApprovalGate:
    """Asks a human to approve an ESCALATE decision.

    A custom `asker` callback may be injected (tests, alternative UIs). The
    default asker prompts on the controlling terminal (/dev/tty), NOT stdin —
    in the MCP proxy, stdin is the protocol stream and must never be consumed
    for prompts.
    """

    def __init__(self, asker: Callable[[str], str] | None = None,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 history: ApprovalHistory | None = None):
        self._asker = asker
        self.timeout_seconds = timeout_seconds
        self.history = history

    def request_approval(self, decision: Decision) -> ApprovalResult:
        history_line = ""
        if self.history is not None:
            try:
                history_line = f"{self.history.prompt_line(decision.action)}\n"
            except Exception:
                history_line = ""   # history is advisory; its failure never blocks the ask
        prompt = (
            "\n=== WARDEN: HUMAN APPROVAL REQUIRED ===\n"
            f"{decision.explain()}\n"
            f"{history_line}"
            "Approve this action? [y/N] "
        )
        try:
            if self._asker is not None:
                answer = self._asker(prompt)
                return self._interpret(answer, "callback")
            return self._ask_tty(prompt)
        except Exception as e:  # fail closed on ANY error while asking
            return ApprovalResult(False, "error", f"approval prompt failed: {e!r}")

    def _interpret(self, answer: str | None, method: str) -> ApprovalResult:
        if answer is None:
            return ApprovalResult(False, "timeout",
                                  f"no answer within {self.timeout_seconds}s; denied (timeout never means allow)")
        if answer.strip().lower() in ("y", "yes"):
            return ApprovalResult(True, method, "explicitly approved by human")
        return ApprovalResult(False, method, f"not approved (answer: {answer.strip()!r})")

    def _ask_tty(self, prompt: str) -> ApprovalResult:
        try:
            tty = open("/dev/tty", "r+")
        except OSError:
            return ApprovalResult(
                False, "unavailable",
                "no controlling terminal to ask a human on; denied (fail closed)")
        with tty:
            tty.write(prompt)
            tty.flush()
            answer: list[str | None] = [None]

            def _read():
                try:
                    answer[0] = tty.readline()
                except Exception:
                    answer[0] = None

            t = threading.Thread(target=_read, daemon=True)
            t.start()
            t.join(self.timeout_seconds)
            if t.is_alive():
                tty.write("\n(timed out — denied)\n")
                return self._interpret(None, "tty")
            return self._interpret(answer[0], "tty")


class EscalatingApprovalGate:
    """A chain of gates for ABSENCE, never for overruling.

    Gates are tried in order. An explicit human answer — approve OR reject —
    ends the chain immediately: a "no" from the first approver is a "no",
    and asking the next person to overrule it would turn escalation into
    approval-shopping. Only non-answers (timeout, no terminal, prompt error)
    move to the next gate. A chain that exhausts without any human answer
    resolves to DENY, exactly like a single silent gate.
    """

    HUMAN_ANSWERED = ("callback", "tty")

    def __init__(self, gates: list[ApprovalGate]):
        if not gates:
            raise ValueError("escalation chain needs at least one gate")
        self.gates = gates

    def request_approval(self, decision: Decision) -> ApprovalResult:
        last: ApprovalResult | None = None
        for i, gate in enumerate(self.gates):
            result = gate.request_approval(decision)
            if result.approved or result.method in self.HUMAN_ANSWERED:
                if i > 0:
                    result = ApprovalResult(
                        result.approved, result.method,
                        f"{result.detail} (answered at escalation level {i + 1})")
                return result
            last = result
        return ApprovalResult(
            False, "timeout",
            f"escalation chain exhausted ({len(self.gates)} approver(s), "
            f"no human answered; last: {last.detail if last else 'n/a'}) — denied")
