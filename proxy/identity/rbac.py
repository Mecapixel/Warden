"""
proxy/identity/rbac.py  (v4)

Agent RBAC — invoking-user permissions vs. agent tool scopes.

Two different identities meet at every tool call, and conflating them is the
classic confused-deputy setup:

  THE INVOKING USER — the human (or service) the agent is working for. Their
  role says what THEY are entitled to have done on their behalf.

  THE AGENT PROCESS — the workload Warden is gating. Its scope says what
  this deployment of the agent is entitled to do for anyone.

The effective permission is the INTERSECTION. Same law as v3 egress scopes:
the agent scope can only NARROW what the user's role grants, never widen it
— otherwise a compromised agent config could quietly grant itself tools the
user was never entitled to, and a privileged user could push the agent past
its deployment scope.

Zero trust at the identity layer means deny-by-default for identities too:
an unknown user has no role, and no role means no tools (RBAC-001), unless
the operator deliberately configured a default_role — opting INTO anonymous
access, never out of it.

Roles also carry the capability grants a session opens with (v4 sessions
call `role_capabilities()` at open time), so "what can this user do" and
"what grants does their session hold" are one declaration in policy, not
two lists that drift apart.
"""

from dataclasses import dataclass


@dataclass
class RbacVerdict:
    permitted: bool
    rule: str | None      # RBAC-001 (user/role), RBAC-002 (agent scope)
    reason: str
    role: str | None = None


def _tool_listed(tool: str, tools: list[str]) -> bool:
    """Exact or family-wildcard match. '*' grants all; 'fs_*' grants a
    prefix family. A wildcard is honored only because the OPERATOR wrote it
    into policy — nothing at runtime can introduce one."""
    for entry in tools or []:
        e = str(entry).strip()
        if e == "*" or e == tool:
            return True
        if e.endswith("*") and tool.startswith(e[:-1]):
            return True
    return False


class Rbac:
    """Built from policy `identity.rbac`. Answers check(user, tool).

    Config shape:
        identity:
          rbac:
            enabled: true
            default_role: null          # unknown users are denied
            agent_scope: [read_file, http_get]   # optional narrowing
            roles:
              analyst:
                tools: [read_file, http_get]
                capabilities:
                  - {capability: filesystem.read, target: "*"}
                  - {capability: network.egress,  target: "*.trusted.org"}
              operator:
                tools: ["*"]
            users:
              meca: operator
              agent: analyst
    """

    def __init__(self, cfg: dict | None):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled"))
        self.roles: dict[str, dict] = dict(cfg.get("roles") or {})
        self.users: dict[str, str] = {
            str(u): str(r) for u, r in (cfg.get("users") or {}).items()
        }
        self.default_role = cfg.get("default_role")
        # None means "no agent scope declared" — no narrowing. An EMPTY list
        # is a declared scope of nothing: the agent may run no tools. The
        # distinction matters and is preserved.
        self.agent_scope: list[str] | None = cfg.get("agent_scope")

    # ------------------------------------------------------------------ #
    def role_of(self, user: str) -> str | None:
        role = self.users.get(user)
        if role is None:
            role = self.default_role
        if role is not None and role not in self.roles:
            # A user mapped to an undeclared role is a configuration hole;
            # it resolves to "no role", which resolves to deny.
            return None
        return role

    def check(self, user: str, tool: str) -> RbacVerdict:
        """The intersection check. Not enabled -> permitted (v1-v3 behavior
        unchanged for policies that never declared an identity block)."""
        if not self.enabled:
            return RbacVerdict(True, None, "rbac not enabled", role=None)

        role = self.role_of(user)
        if role is None:
            return RbacVerdict(
                False, "RBAC-001",
                f"user {user!r} has no role (unknown identity, no default_role) — deny by default")

        role_tools = (self.roles.get(role) or {}).get("tools") or []
        if not _tool_listed(tool, role_tools):
            return RbacVerdict(
                False, "RBAC-001",
                f"role {role!r} (user {user!r}) does not permit tool {tool!r}",
                role=role)

        if self.agent_scope is not None and not _tool_listed(tool, self.agent_scope):
            return RbacVerdict(
                False, "RBAC-002",
                f"tool {tool!r} is permitted to user {user!r} but outside this "
                f"agent deployment's scope — scopes narrow, never widen",
                role=role)

        return RbacVerdict(True, None, f"role {role!r} permits {tool!r}", role=role)

    # ------------------------------------------------------------------ #
    def role_capabilities(self, user: str) -> list[dict]:
        """The capability grants a session for this user opens with."""
        role = self.role_of(user)
        if role is None:
            return []
        out = []
        for entry in (self.roles.get(role) or {}).get("capabilities") or []:
            if isinstance(entry, dict) and entry.get("capability"):
                out.append({"capability": str(entry["capability"]),
                            "target": str(entry.get("target", "*"))})
        return out
