"""
warden/adapters/base.py  (v7)

The in-process gate every framework adapter routes through.

The MCP transport (warden/transport/mcp.py) mediates tool calls that cross a
process boundary. Frameworks like the OpenAI Agents SDK, LangChain, AutoGen,
and CrewAI invoke tools as plain Python callables INSIDE the agent process —
there is no wire to sit on. WardenGate is the same pipeline
(Normalize -> Policy -> Approve -> Execute -> Audit) applied at the callable
boundary instead of the protocol boundary.

Three laws, all inherited from the rest of Warden:

  DENY BY DEFAULT.  A tool the policy does not name gets whatever the policy
                    engine says for unknown tools — the gate adds no
                    permissiveness of its own and has no allowlist bypass.
  THE GATE DECIDES BEFORE THE TOOL RUNS.  On DENY the wrapped callable is
                    never invoked; WardenDenied carries the full Decision so
                    the caller (and the audit chain) can explain why.
  EVERY CALL IS AUDITED.  Allowed, denied, escalated, approved, refused —
                    each writes one audit record BEFORE control returns,
                    linked by parent_event_id where an approval follows a
                    decision.

The framework-specific modules (openai_agents, langchain, autogen, crewai)
are thin: they only know how to find the (name, callable) pairs inside each
framework's tool shape and hand them here. None of them import their
framework — they duck-type, so Warden adds zero dependencies.
"""

from __future__ import annotations

from typing import Any, Callable

from warden.audit.log import AuditLog
from warden.core.decision import Decision, Verdict
from warden.core.mission import Mission
from warden.core.request import Request
from warden.policy.engine import PolicyEngine
from warden.runtime.approval import ApprovalGate, ApprovalResult


class WardenDenied(PermissionError):
    """Raised instead of running a tool the policy denied (or a human refused).

    Carries the full Decision so callers can render decision.explain().
    """

    def __init__(self, decision: Decision, note: str = ""):
        self.decision = decision
        msg = f"[warden] {decision.verdict.value} {decision.action}: {decision.reason}"
        if note:
            msg += f" ({note})"
        super().__init__(msg)


class WardenGate:
    """Mediate in-process tool callables through the Warden pipeline.

    gate = WardenGate(policy_path, audit_path)
    safe_fn = gate.wrap("read_file", read_file)   # one callable
    result  = safe_fn(path="notes.txt")

    ESCALATE verdicts go to the ApprovalGate. With no asker configured the
    gate asks on the controlling TTY; in headless contexts approval times out
    and the call is refused — fail closed, never fail open.
    """

    def __init__(self, policy_path: str, audit_path: str,
                 user: str = "anonymous",
                 mission: Mission | None = None,
                 approval: ApprovalGate | None = None,
                 session: Any = None):
        self.engine = PolicyEngine(policy_path)
        self.audit = AuditLog(audit_path)
        self.user = user
        self.mission = mission
        self.approval = approval or ApprovalGate()
        self.session = session

    # ------------------------------------------------------------------ #

    def decide(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Run the pipeline up to (not including) execution. Audited."""
        request = Request.normalize(tool, args or {}, user=self.user)
        decision = self.engine.decide(request, self.mission, session=self.session)
        decision.audit_id = self.audit.record(
            tool, decision.verdict.value, decision.reason,
            detail={
                "rule": decision.rule,
                "risk_score": decision.risk_score,
                "args": request.args,
                "user": self.user,
                "adapter": "in-process",
            },
        )
        return decision

    def call(self, tool: str, fn: Callable[..., Any],
             args: dict[str, Any] | None = None) -> Any:
        """Decide, then (only on permission) execute. The enforcement point."""
        args = args or {}
        decision = self.decide(tool, args)

        if decision.verdict == Verdict.DENY:
            raise WardenDenied(decision)

        if decision.verdict == Verdict.ESCALATE:
            result: ApprovalResult = self.approval.request_approval(decision)
            self.audit.record(
                tool, "APPROVED" if result.approved else "REFUSED",
                f"human approval: {result.detail}",
                detail={"method": result.method},
                parent_event_id=decision.audit_id,
            )
            if not result.approved:
                raise WardenDenied(decision, note=f"approval {result.method}: {result.detail}")

        # ALLOW / REDACT / approved ESCALATE. Path canonicalization decided by
        # the engine MUST be applied, same contract as the MCP transport:
        # the checked path and the executed path are the same string.
        if decision.path_rewrites:
            args = {**args, **decision.path_rewrites}
        return fn(**args)

    def wrap(self, tool: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Return a callable enforcing the pipeline around `fn`."""
        def guarded(**kwargs: Any) -> Any:
            return self.call(tool, fn, kwargs)
        guarded.__name__ = getattr(fn, "__name__", tool)
        guarded.__doc__ = getattr(fn, "__doc__", None)
        guarded.__wrapped__ = fn
        guarded.__warden_tool__ = tool
        return guarded

    def close(self) -> None:
        self.audit.close()
