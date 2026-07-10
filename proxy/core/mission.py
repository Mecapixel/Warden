"""
proxy/core/mission.py

Mission Mode — least privilege with a human-understandable mental model.

Before an agent runs, the user declares a MISSION: a plain statement of intent
plus the set of tool capabilities the mission legitimately needs. Anything the
agent tries that falls outside the mission's allowed set is denied automatically
and contributes risk — no matter what a clever prompt talked the agent into.

This is the simple, reliable version of "intent verification." It does NOT try
to semantically judge whether an action matches a goal (that is a hard research
problem parked in v6). Instead it uses an explicit allowlist per mission, which
is honest, testable, and gives the user a clear mental model:

    Mission:  "Review my Python project"
    Allowed:  filesystem.read, filesystem.list, python.run, git.status
    Denied:   everything else (internet, shell, delete, upload, ...)

FAIL-CLOSED RULE: a declared mission with an EMPTY capability set denies
everything. The only way Mission Mode abstains is the explicit Mission.open()
sentinel — "no mission declared" must be a deliberate choice, never the silent
result of forgetting to list capabilities.
"""

from dataclasses import dataclass, field


@dataclass
class Mission:
    """A declared unit of intended work with an explicit capability allowlist."""
    statement: str                                  # human-readable goal
    allowed_tools: set[str] = field(default_factory=set)
    declared: bool = True                           # False only via Mission.open()

    @classmethod
    def open(cls) -> "Mission":
        """The permissive 'no mission declared' sentinel — the ONLY abstaining
        mission. When no mission is set, Mission Mode adds no constraints and
        the policy engine falls back to its normal tool-tier rules. Declaring
        a mission is opt-in but strongly recommended — it is the difference
        between 'trust the prompt' and 'trust the boundary'."""
        return cls(statement="(no mission declared)", allowed_tools=set(), declared=False)

    @property
    def is_declared(self) -> bool:
        return self.declared

    def permits(self, tool: str) -> bool:
        """True iff the tool is within this mission's allowed capability set.

        Undeclared (Mission.open()) abstains and returns True, deferring to the
        rest of the policy pipeline. A DECLARED mission is strict: only tools in
        the allowlist pass — an empty allowlist therefore denies everything
        (fail closed), rather than silently granting everything (fail open).
        """
        if not self.declared:
            return True
        return tool in self.allowed_tools

    def check(self, tool: str) -> tuple[bool, str]:
        """Return (permitted, reason) for auditability."""
        if not self.declared:
            return True, "no mission declared; mission check abstains"
        if tool in self.allowed_tools:
            return True, f"tool {tool!r} is within the mission's allowed capabilities"
        allowed = ", ".join(sorted(self.allowed_tools)) if self.allowed_tools else "(none)"
        return False, (
            f"tool {tool!r} is outside the declared mission "
            f"({self.statement!r}); mission allows only: {allowed}"
        )
