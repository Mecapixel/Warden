"""
proxy/runtime/approval.py

Minimal human approval gate — the v1 human-in-the-loop control.

When the policy engine returns ESCALATE, execution pauses and a human answers
yes/no. Three properties are non-negotiable:

  1. FAIL CLOSED. No terminal to ask on, an exception while asking, a timeout
     waiting — every failure mode resolves to DENY. There is no code path
     where silence becomes consent.
  2. The human sees the full explainable Decision (rule, risk, contributors,
     recommended fix) before answering — approval of an unexplained action is
     not informed approval.
  3. Every answer is auditable: the gate returns a structured result the
     mediator writes to the audit chain, parent-linked to the decision that
     triggered it.

The full approval model (per-capability approval policies, approval history,
escalation chains) is v4; this gate is deliberately the thin version.
"""

import sys
import threading
from dataclasses import dataclass
from typing import Callable

from proxy.core.decision import Decision

DEFAULT_TIMEOUT_SECONDS = 120


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
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS):
        self._asker = asker
        self.timeout_seconds = timeout_seconds

    def request_approval(self, decision: Decision) -> ApprovalResult:
        prompt = (
            "\n=== WARDEN: HUMAN APPROVAL REQUIRED ===\n"
            f"{decision.explain()}\n"
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
