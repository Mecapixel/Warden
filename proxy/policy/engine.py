"""
proxy/policy/engine.py

The decision core. Takes a normalized Request, runs it through the guards,
accumulates a RiskAssessment, and returns a rich, explainable Decision.

Pipeline order (deliberate, by blast radius):
    0. Mission check                       (declared intent is the outer wall)
    0b. Tool registry                      (least privilege at the registry)
    1. Tool known & permitted?             (deny-by-default; unknown => deny)
    2. Hard-deny tier?                     (explicitly forbidden tools)
    3. Path containment (filesystem)       (escape => hard-boundary deny)
    4. Credential screening on arguments   (secrets block; PII adds risk)
    5. Tier -> band reconciliation         (auto/escalate + accumulated risk)

The engine is pure: it makes decisions but performs no I/O (no forwarding, no
human prompt, no logging). That purity is what makes it fully testable against
the synthetic attack suite. Rule IDs (FS-###, TOOL-###, SEC-###) let every
decision cite the exact rule that governed it.

POLICY VALIDATION: the policy file is validated at construction and the engine
refuses to start on an invalid policy (fail closed at startup). A gateway that
limps along with a half-loaded policy is worse than one that will not start.
"""

from typing import Any

import yaml

from proxy.core.request import Request
from proxy.core.risk import RiskAssessment
from proxy.core.decision import Decision, Verdict
from proxy.core.mission import Mission
from proxy.guards.canonicalize import canonicalize_within, PathTraversalError
from proxy.guards.egress import check_url, EgressViolation
from proxy.core.textnorm import harden
from proxy.inspect import redactor


# Fallback argument keys treated as filesystem paths when a tool's policy does
# not declare `path_args` explicitly. Declaring path_args per tool in
# policy.yaml is preferred: the policy, not a guess list, should be the
# authority on which arguments carry paths.
_DEFAULT_PATH_ARG_KEYS = ("path", "file", "filename", "directory", "dir")

# Fallback argument keys treated as network destinations when a tool's policy
# does not declare `url_args` explicitly.
_DEFAULT_URL_ARG_KEYS = ("url", "uri", "endpoint", "address", "host")

_VALID_TIERS = {"auto", "escalate", "deny"}


class PolicyValidationError(Exception):
    """Raised when policy.yaml is missing required fields or malformed."""


def _validate_policy(policy: Any) -> dict:
    if not isinstance(policy, dict):
        raise PolicyValidationError("policy.yaml must be a mapping at the top level")
    root = policy.get("workspace_root")
    if not root or not isinstance(root, str):
        raise PolicyValidationError("policy.yaml: 'workspace_root' (string) is required")
    tools = policy.get("tools", {})
    if not isinstance(tools, dict):
        raise PolicyValidationError("policy.yaml: 'tools' must be a mapping of tool -> spec")
    for name, spec in tools.items():
        if not isinstance(spec, dict):
            raise PolicyValidationError(f"policy.yaml: tools.{name} must be a mapping")
        tier = spec.get("tier", "deny")
        if tier not in _VALID_TIERS:
            raise PolicyValidationError(
                f"policy.yaml: tools.{name}.tier is {tier!r}; must be one of {sorted(_VALID_TIERS)}"
            )
        for arg_field in ("path_args", "url_args"):
            val = spec.get(arg_field)
            if val is not None and (
                not isinstance(val, list) or not all(isinstance(k, str) for k in val)
            ):
                raise PolicyValidationError(f"policy.yaml: tools.{name}.{arg_field} must be a list of strings")
    registry = policy.get("tool_registry", [])
    if registry is not None and not isinstance(registry, list):
        raise PolicyValidationError("policy.yaml: 'tool_registry' must be a list")
    return policy


class PolicyEngine:
    def __init__(self, policy_path: str):
        with open(policy_path) as fh:
            self.policy = _validate_policy(yaml.safe_load(fh))
        self.workspace_root = self.policy["workspace_root"]
        self.tools = self.policy.get("tools", {})
        self.redaction_cfg = self.policy.get("redaction", {})
        # Tool allowlist registry: if a non-empty `tool_registry` list is present
        # in policy, ONLY those tools may run — least privilege at the registry
        # level, on top of per-tool tiers. An empty/absent registry means the
        # per-tool `tools:` map is the authority (deny-by-default still applies
        # to anything not listed there).
        self.tool_registry = set(self.policy.get("tool_registry", []) or [])
        self.egress_cfg = self.policy.get("egress", {}) or {}

    def decide(self, request: Request, mission: Mission | None = None) -> Decision:
        """Evaluate a normalized Request and return a rich Decision.

        If a Mission is supplied, the mission check runs first (after
        normalization): an action outside the declared mission is denied before
        any other evaluation, because the strongest signal that something is
        wrong is 'the agent is doing something the user never asked for.'
        """
        risk = RiskAssessment()
        tool = request.tool
        args = request.args
        mission = mission or Mission.open()

        # 0. Mission check — is this action even part of the declared job?
        permitted, mreason = mission.check(tool)
        if not permitted:
            risk.add("mission_violation", mreason)
            return Decision.from_risk(
                Verdict.DENY, rule="MIS-001", action=tool, assessment=risk,
                reason="Action is outside the declared mission.",
                recommended_fix="If this action is legitimately needed, add its capability to the mission's allowed set.",
                request_id=request.request_id,
            )

        # 0b. Tool registry — is this tool allowed to exist at all?
        if self.tool_registry and tool not in self.tool_registry:
            risk.add("unregistered_tool", f"tool {tool!r} is not in the allowlist registry")
            return Decision.from_risk(
                Verdict.DENY, rule="REG-001", action=tool, assessment=risk,
                reason="Tool is not in the allowlist registry.",
                recommended_fix="Add the tool to tool_registry in policy.yaml if it should be permitted.",
                request_id=request.request_id,
            )

        # 1. Deny-by-default: unknown tools are a risk, not a silent pass.
        spec = self.tools.get(tool)
        if spec is None:
            risk.add("unknown_tool", f"tool {tool!r} is not defined in policy")
            return Decision.from_risk(
                Verdict.DENY, rule="TOOL-001", action=tool, assessment=risk,
                reason=f"Tool {tool!r} is not in policy (deny by default).",
                recommended_fix="Add the tool to policy.yaml with an explicit tier if this access is intended.",
                request_id=request.request_id,
            )

        tier = spec.get("tier", "deny")

        # 2. Hard deny tier.
        if tier == "deny":
            risk.add("policy_deny_tier", f"tool {tool!r} is explicitly tier: deny")
            return Decision.from_risk(
                Verdict.DENY, rule="TOOL-002", action=tool, assessment=risk,
                reason=f"Tool {tool!r} is explicitly denied by policy (tier: deny).",
                recommended_fix="Change the tool's tier in policy.yaml if this access is intended.",
                request_id=request.request_id,
            )

        # 3. Path containment for path-bearing arguments. The tool's policy may
        # declare exactly which args carry paths (`path_args`); the default key
        # list is only a fallback for tools that do not declare.
        path_keys = spec.get("path_args") or _DEFAULT_PATH_ARG_KEYS
        # path_rewrites maps EVERY path-bearing argument key to its canonical
        # resolved form. The transport must rewrite the forwarded arguments to
        # these values so the path Warden checked and the path the server
        # executes are the same string (closes the check-vs-execute gap where
        # a server with a different cwd resolves a relative path elsewhere).
        # target/safe_path record the FIRST path arg for attribution; every
        # arg is still checked, and every arg gets a rewrite entry.
        path_rewrites: dict[str, str] = {}
        safe_path = None
        target = None
        for key in path_keys:
            if key in args:
                requested = str(args[key])
                try:
                    resolved = canonicalize_within(self.workspace_root, requested)
                except PathTraversalError:
                    risk.add("filesystem_escape", f"path {requested!r} resolves outside the workspace")
                    return Decision.from_risk(
                        Verdict.DENY, rule="FS-004", action=tool, assessment=risk,
                        reason="Path resolves outside the approved workspace.",
                        target=requested,
                        recommended_fix="Move the file into the approved workspace, or update workspace_root/policy.yaml if this access is intentional.",
                        request_id=request.request_id,
                    )
                path_rewrites[key] = str(resolved)
                if target is None:
                    target = requested
                    safe_path = str(resolved)

        # 3b. Egress allowlist for URL-bearing arguments. An unlisted network
        # destination is denied outright — exfiltration dies at the host check.
        if self.egress_cfg.get("enabled"):
            url_keys = spec.get("url_args") or _DEFAULT_URL_ARG_KEYS
            allowlist = self.egress_cfg.get("allowed_hosts", []) or []
            for key in url_keys:
                if key in args:
                    url = str(args[key])
                    try:
                        check_url(url, allowlist)
                    except EgressViolation as ev:
                        risk.add("egress_violation",
                                 f"destination host {ev.host!r} is not in the egress allowlist")
                        return Decision.from_risk(
                            Verdict.DENY, rule="EGR-001", action=tool, assessment=risk,
                            reason="Network destination is not in the egress allowlist.",
                            target=url,
                            recommended_fix="Add the host to egress.allowed_hosts in policy.yaml if this destination is intended.",
                            request_id=request.request_id,
                        )

        # 4. Secret/PII screening on arguments. Credentials block the call;
        # PII adds risk and is surfaced to the human at the tier gate rather
        # than hard-blocking legitimate work that merely mentions an email.
        if self.redaction_cfg.get("enabled") and spec.get("inspect_args"):
            detectors = self.redaction_cfg.get("detectors")
            joined = harden(" ".join(str(v) for v in args.values()))
            findings = redactor.scan(joined, detectors)
            if findings:
                cred = sorted({f.detector for f in findings if f.detector in redactor.CREDENTIAL_DETECTORS})
                pii = sorted({f.detector for f in findings if f.detector not in redactor.CREDENTIAL_DETECTORS})
                if cred and self.redaction_cfg.get("block_secrets_in_args"):
                    risk.add("secret_in_transit", f"credential(s) detected in arguments: {', '.join(cred)}")
                    return Decision.from_risk(
                        Verdict.DENY, rule="SEC-001", action=tool, assessment=risk,
                        reason="A secret or credential was detected in the tool arguments.",
                        target=target,
                        recommended_fix="Remove the secret from the tool call; use a secret manager or scoped token instead of passing raw credentials.",
                        safe_path=safe_path,
                        request_id=request.request_id,
                    )
                if pii:
                    risk.add("pii_in_transit", f"PII detected in arguments: {', '.join(pii)}")

        # 5. Tier -> band reconciliation.
        # No hard-boundary signal fired. The tier sets the floor; accumulated
        # soft risk can still raise it.
        if tier == "escalate" or risk.band == "escalate":
            return Decision.from_risk(
                Verdict.ESCALATE, rule="TOOL-003", action=tool, assessment=risk,
                reason=f"Tool {tool!r} requires human approval before proceeding.",
                target=target, safe_path=safe_path, path_rewrites=path_rewrites,
                request_id=request.request_id,
            )

        # tier == auto and no meaningful risk -> allow
        return Decision.from_risk(
            Verdict.ALLOW, rule="TOOL-004", action=tool, assessment=risk,
            reason=f"Tool {tool!r} is permitted (tier: auto) and no risk signals fired.",
            target=target, safe_path=safe_path, path_rewrites=path_rewrites,
            request_id=request.request_id,
        )

    def response_policy(self, tool: str) -> dict[str, bool]:
        """What to do with a tool's RETURNED data before handing it to the agent."""
        spec = self.tools.get(tool, {})
        return {
            "inspect_response": bool(spec.get("inspect_response")),
            "redact_response": bool(self.redaction_cfg.get("enabled")),
            "inbound_inspection": bool(self.policy.get("inbound_inspection", {}).get("enabled")),
        }
