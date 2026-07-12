"""
warden/policy/engine.py

The decision core. Takes a normalized Request, runs it through the guards,
accumulates a RiskAssessment, and returns a rich, explainable Decision.

Pipeline order (deliberate, by blast radius):
    0. Mission check                       (declared intent is the outer wall)
    0b. Tool registry                      (least privilege at the registry)
    1. Tool known & permitted?             (deny-by-default; unknown => deny)
    2. Hard-deny tier?                     (explicitly forbidden tools)
    2b. Tool-call schema validation        (known tool, wrong shape => deny)
    3. Path containment (filesystem)       (escape => hard-boundary deny)
    3b. Network battery (v3)               (allowlist, scope, scheme, sinkhole,
                                            reputation, SSRF resolve-validate)
    4. Credential screening on arguments   (secrets block; PII adds risk)
    5. Tier -> band reconciliation         (auto/escalate + accumulated risk)

The engine is pure in the sense that matters: it makes decisions, performs no
forwarding, no human prompts, no logging. The one I/O it owns is resolution —
filesystem canonicalization in step 3 and DNS resolution in step 3b — because
both ARE the check: a path or host cannot be judged without resolving what it
actually points at. The DNS resolver is injectable (constructor arg), so the
full battery runs in tests with zero real network traffic, and a deployment
can substitute a caching or DoH resolver. Rule IDs (FS-###, TOOL-###, SEC-###,
EGR-###, SSRF-###, DNS-###, REP-###) let every decision cite the exact rule
that governed it.

POLICY VALIDATION: the policy file is validated at construction and the engine
refuses to start on an invalid policy (fail closed at startup). A gateway that
limps along with a half-loaded policy is worse than one that will not start.
"""

from typing import Any

import yaml

from warden.core.request import Request
from warden.core.risk import RiskAssessment
from warden.core.decision import Decision, Verdict
from warden.core.mission import Mission
from warden.guards.canonicalize import canonicalize_within, PathTraversalError
from warden.guards.egress import extract_host
from warden.core.textnorm import harden
from warden.inspect import redactor
from warden.network.guard import NetworkGuard
from warden.network.dnspin import Resolver
from warden.identity.rbac import Rbac
from warden.runtime.approval import ApprovalPolicies, ApprovalPolicyError


# Fallback argument keys treated as filesystem paths when a tool's policy does
# not declare `path_args` explicitly. Declaring path_args per tool in
# policy.yaml is preferred: the policy, not a guess list, should be the
# authority on which arguments carry paths.
_DEFAULT_PATH_ARG_KEYS = ("path", "file", "filename", "directory", "dir")

# Fallback argument keys treated as network destinations when a tool's policy
# does not declare `url_args` explicitly.
_DEFAULT_URL_ARG_KEYS = ("url", "uri", "endpoint", "address", "host")

_VALID_TIERS = {"auto", "escalate", "deny"}
_VALID_UNKNOWN_ACTIONS = {"allow", "escalate", "deny"}


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
        for arg_field in ("path_args", "url_args", "egress_hosts"):
            val = spec.get(arg_field)
            if val is not None and (
                not isinstance(val, list) or not all(isinstance(k, str) for k in val)
            ):
                raise PolicyValidationError(f"policy.yaml: tools.{name}.{arg_field} must be a list of strings")
    registry = policy.get("tool_registry", [])
    if registry is not None and not isinstance(registry, list):
        raise PolicyValidationError("policy.yaml: 'tool_registry' must be a list")

    # v3: the network section, when present, must be structurally sound.
    # An unknown_action typo like 'esclate' silently meaning 'allow' would be
    # a policy that enforces less than the operator wrote — refuse to start.
    network = policy.get("network")
    if network is not None:
        if not isinstance(network, dict):
            raise PolicyValidationError("policy.yaml: 'network' must be a mapping")
        rep = network.get("reputation") or {}
        ua = str(rep.get("unknown_action", "allow")).lower()
        if ua not in _VALID_UNKNOWN_ACTIONS:
            raise PolicyValidationError(
                f"policy.yaml: network.reputation.unknown_action is {ua!r}; "
                f"must be one of {sorted(_VALID_UNKNOWN_ACTIONS)}"
            )
        rl = network.get("rate_limit") or {}
        for scope_name, scope in (("global", rl.get("global") or {}),
                                  *((f"per_tool.{t}", s) for t, s in (rl.get("per_tool") or {}).items())):
            for field_name in ("capacity", "refill_per_second"):
                v = scope.get(field_name)
                if v is not None and (not isinstance(v, (int, float)) or v < 0):
                    raise PolicyValidationError(
                        f"policy.yaml: network.rate_limit.{scope_name}.{field_name} "
                        f"must be a non-negative number"
                    )
        for list_field in ("sinkhole",):
            val = (network.get("dns") or {}).get(list_field)
            if val is not None and (
                not isinstance(val, list) or not all(isinstance(k, str) for k in val)
            ):
                raise PolicyValidationError(f"policy.yaml: network.dns.{list_field} must be a list of strings")

    # v6: the adaptive section, when present, must be structurally sound.
    # The adaptive layer only ever ADDS caution, so validation guards the one
    # way it could betray that: a context rule whose 'floor' is not a real
    # verdict, or a malformed behavioral config.
    adaptive = policy.get("adaptive")
    if adaptive is not None:
        if not isinstance(adaptive, dict):
            raise PolicyValidationError("policy.yaml: 'adaptive' must be a mapping")
        _VERDICTS = {"ALLOW", "REDACT", "ESCALATE", "DENY"}
        for entry in (adaptive.get("context_rules") or []):
            if not isinstance(entry, dict) or "when" not in entry or "floor" not in entry:
                raise PolicyValidationError(
                    "policy.yaml: each adaptive.context_rules entry needs "
                    "'when' and 'floor'")
            if entry["floor"] not in _VERDICTS:
                raise PolicyValidationError(
                    f"policy.yaml: adaptive context floor {entry['floor']!r} "
                    f"is not one of {sorted(_VERDICTS)} (ADAPT-002)")
        behavior = adaptive.get("behavior")
        if behavior is not None:
            if not isinstance(behavior, dict):
                raise PolicyValidationError(
                    "policy.yaml: adaptive.behavior must be a mapping")
            if int(behavior.get("warmup_calls", 0)) < 0:
                raise PolicyValidationError(
                    "policy.yaml: adaptive.behavior.warmup_calls cannot be negative")

    # v5: the containment section, when present, must be structurally sound
    # — same contract again: a typo that would contain LESS than the
    # operator wrote is refused at startup.
    containment = policy.get("containment")
    if containment is not None:
        if not isinstance(containment, dict):
            raise PolicyValidationError("policy.yaml: 'containment' must be a mapping")
        from warden.containment.backends import ISOLATION_ORDER
        req = containment.get("required_isolation", "docker")
        if req not in ISOLATION_ORDER:
            raise PolicyValidationError(
                f"policy.yaml: containment.required_isolation {req!r} is not "
                f"one of {ISOLATION_ORDER}")
        if req == "wasmtime" and containment.get("enabled") \
                and not containment.get("wasm_module"):
            raise PolicyValidationError(
                "policy.yaml: containment.required_isolation is 'wasmtime' "
                "but no wasm_module is declared — a native command cannot "
                "run on the wasm rung")
        try:
            from warden.containment.quotas import Quotas, QuotaError
            Quotas.from_policy(containment.get("quotas"))
        except QuotaError as exc:
            raise PolicyValidationError(f"policy.yaml: {exc}") from exc
        pm = containment.get("process_monitor")
        if pm is not None:
            if not isinstance(pm, dict):
                raise PolicyValidationError(
                    "policy.yaml: containment.process_monitor must be a mapping")
            try:
                from warden.containment.procmon import ProcessMonitor
                ProcessMonitor(pm, snapshot_provider=lambda: [])
            except ValueError as exc:
                raise PolicyValidationError(
                    f"policy.yaml: containment.process_monitor: {exc}") from exc

    # v4: the identity section, when present, must be structurally sound.
    # The same rule as v3's network block: a typo that silently enforces
    # LESS than the operator wrote is refused at startup, never discovered
    # in an incident review.
    identity = policy.get("identity")
    if identity is not None:
        if not isinstance(identity, dict):
            raise PolicyValidationError("policy.yaml: 'identity' must be a mapping")
        rbac = identity.get("rbac") or {}
        roles = rbac.get("roles")
        if roles is not None and not isinstance(roles, dict):
            raise PolicyValidationError("policy.yaml: identity.rbac.roles must be a mapping")
        for rname, rdef in (roles or {}).items():
            if not isinstance(rdef, dict):
                raise PolicyValidationError(
                    f"policy.yaml: identity.rbac.roles.{rname} must be a mapping")
            tools = rdef.get("tools")
            if tools is not None and (
                not isinstance(tools, list) or not all(isinstance(t, str) for t in tools)
            ):
                raise PolicyValidationError(
                    f"policy.yaml: identity.rbac.roles.{rname}.tools must be a list of strings")
        users = rbac.get("users")
        if users is not None and not isinstance(users, dict):
            raise PolicyValidationError("policy.yaml: identity.rbac.users must be a mapping")
        default_role = rbac.get("default_role")
        if default_role is not None and default_role not in (roles or {}):
            raise PolicyValidationError(
                f"policy.yaml: identity.rbac.default_role {default_role!r} is not a declared role")
        for user, role in (users or {}).items():
            if role not in (roles or {}):
                raise PolicyValidationError(
                    f"policy.yaml: identity.rbac.users.{user} maps to undeclared role {role!r}")
        try:
            ApprovalPolicies((identity.get("approval") or {}).get("policies"))
        except ApprovalPolicyError as exc:
            raise PolicyValidationError(f"policy.yaml: {exc}") from exc
        memory = identity.get("memory") or {}
        if memory.get("enabled") and memory.get("encrypt"):
            try:
                import cryptography.fernet  # noqa: F401
            except ImportError:
                raise PolicyValidationError(
                    "policy.yaml: identity.memory.encrypt is enabled but the "
                    "'cryptography' package is not installed. Install it with "
                    "'pip install cryptography', or disable encryption — a "
                    "security tool must never quietly downgrade the protection "
                    "the operator configured."
                )

    # v1.5.5: if the policy explicitly enables the presidio detector, the
    # backend must actually load. A security tool must never quietly
    # downgrade to weaker detection than the operator configured.
    redaction = policy.get("redaction", {}) or {}
    detectors = redaction.get("detectors") or []
    if "presidio" in detectors:
        from warden.inspect.presidio_backend import available
        ok, why = available()
        if not ok:
            raise PolicyValidationError(
                "policy.yaml: redaction.detectors includes 'presidio' but the "
                f"backend cannot load ({why}). Install it with "
                "'pip install presidio-analyzer' plus a spaCy model, or remove "
                "'presidio' from the detector list."
            )
    return policy


class PolicyEngine:
    def __init__(self, policy_path: str, resolver: Resolver | None = None):
        with open(policy_path) as fh:
            try:
                loaded = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                raise PolicyValidationError(
                    f"policy file is not valid YAML ({policy_path}): {exc}"
                ) from exc
        self.policy = _validate_policy(loaded)
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
        self.network_cfg = self.policy.get("network", {}) or {}
        # v3: one NetworkGuard instance for the engine's lifetime, so the DNS
        # pin cache and reputation cache accumulate across requests — rebinding
        # detection is only possible with memory. The transport reuses this
        # same instance for redirect-hop re-checks: one battery, one path.
        self.network_guard = NetworkGuard(self.egress_cfg, self.network_cfg,
                                          resolver=resolver)
        # v4: identity layer. Rbac and ApprovalPolicies are engine-owned
        # because they shape Decisions; sessions and memory vaults are
        # runtime objects owned by the mediator/operator. Absent identity
        # block -> both are inert and v1-v3 behavior is unchanged.
        self.identity_cfg = self.policy.get("identity", {}) or {}
        self.rbac = Rbac(self.identity_cfg.get("rbac"))
        self.capabilities_enabled = bool(
            (self.identity_cfg.get("capabilities") or {}).get("enabled"))
        self.approval_policies = ApprovalPolicies(
            (self.identity_cfg.get("approval") or {}).get("policies"))

    def decide(self, request: Request, mission: Mission | None = None,
               session=None) -> Decision:
        """Evaluate a normalized Request and return a rich Decision.

        If a Mission is supplied, the mission check runs first (after
        normalization): an action outside the declared mission is denied before
        any other evaluation, because the strongest signal that something is
        wrong is 'the agent is doing something the user never asked for.'

        If a session (v4 SecureSession) is supplied and capabilities are
        enabled in policy, tools that declare a required capability are
        checked against the session's signed grants.
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

        # 1b. v4 RBAC — the invoking user's role, intersected with the agent
        # deployment's scope. Placed after existence checks (an unknown tool
        # is an unknown tool regardless of who asks) and before tiers: a tool
        # the identity layer forbids never reaches capability or risk logic.
        rv = self.rbac.check(request.user, tool)
        if not rv.permitted:
            signal = ("agent_scope_violation" if rv.rule == "RBAC-002"
                      else "rbac_violation")
            risk.add(signal, rv.reason)
            return Decision.from_risk(
                Verdict.DENY, rule=rv.rule, action=tool, assessment=risk,
                reason=rv.reason,
                recommended_fix=(
                    "Add the tool to identity.rbac.agent_scope if this deployment should run it."
                    if rv.rule == "RBAC-002" else
                    "Assign the user a role that permits this tool in identity.rbac, or add the tool to their role."),
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

        # 2b. v2: JSON-Schema tool-call validation. If policy declares an
        # `args_schema` for this tool, a call whose arguments don't conform is
        # a structural anomaly — deny it. Deny-by-default already stops unknown
        # tools; this stops KNOWN tools invoked with the wrong shape (a probe
        # for a parser bug, or an agent confused into a malformed call).
        arg_schema = spec.get("args_schema")
        if arg_schema:
            from warden.inspect.schema import check_tool_call
            violation = check_tool_call(args, arg_schema)
            if violation:
                risk.add("schema_violation",
                         f"tool-call arguments failed schema: {violation.detail}")
                return Decision.from_risk(
                    Verdict.DENY, rule="SCHEMA-001", action=tool, assessment=risk,
                    reason=f"Tool call arguments did not conform to the declared schema.",
                    recommended_fix="Correct the argument structure, or adjust args_schema in policy.yaml.",
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

        # 3b. v3 network battery for URL-bearing arguments. One ordered check
        # sequence — scheme, sinkhole, global allowlist, per-tool scope,
        # reputation, SSRF resolve-then-validate — behind a single entry point
        # (NetworkGuard.check_url), so the engine and the redirect inspector
        # cannot drift apart. The guard reports; the engine decides.
        if self.egress_cfg.get("enabled"):
            url_keys = spec.get("url_args") or _DEFAULT_URL_ARG_KEYS
            tool_scope = spec.get("egress_hosts")   # None = no per-tool narrowing
            for key in url_keys:
                if key in args:
                    url = str(args[key])
                    violation = self.network_guard.check_url(url, tool_scope=tool_scope)
                    if violation is not None:
                        risk.add(violation.signal, violation.reason)
                        verdict = (Verdict.ESCALATE
                                   if violation.verdict_hint == "escalate"
                                   else Verdict.DENY)
                        fixes = {
                            "EGR-001": "Add the host to egress.allowed_hosts in policy.yaml if this destination is intended.",
                            "EGR-002": "Add the host to this tool's egress_hosts scope in policy.yaml if this destination is intended.",
                            "EGR-003": "Add the scheme to egress.allowed_schemes in policy.yaml if it is genuinely needed.",
                            "DNS-001": "Remove the host from network.dns.sinkhole if this block is no longer intended.",
                            "REP-001": "The host is on the known-bad list; if that listing is wrong, remove it from network.reputation.known_bad.",
                            "REP-002": "Add the host to network.reputation.known_good, or relax network.reputation.unknown_action.",
                            "SSRF-001": "Agent tool calls have no legitimate route to internal or metadata addresses; if this is truly intended infrastructure access, adjust network.ssrf in policy.yaml deliberately.",
                            "SSRF-002": "This host's DNS now answers with an internal address after previously answering public — treat as hostile until investigated.",
                        }
                        return Decision.from_risk(
                            verdict, rule=violation.rule, action=tool, assessment=risk,
                            reason=violation.reason,
                            target=url,
                            recommended_fix=fixes.get(violation.rule),
                            request_id=request.request_id,
                        )

        # 3c. v4 capability check. A tool that declares `capability:` in its
        # spec requires the session to hold a verified, unexpired, correctly
        # scoped grant for the CANONICAL target — the path after
        # canonicalization, the host after extraction — so a grant scoped to
        # /workspace/data cannot be stretched with '..' games or URL dressing
        # (those were killed upstream). No session, no grant, closed session:
        # all the same answer.
        required_cap = str(spec.get("capability") or "").strip().lower()
        if self.capabilities_enabled and required_cap:
            if required_cap == "network.egress":
                cap_target = None
                url_keys = spec.get("url_args") or _DEFAULT_URL_ARG_KEYS
                for key in url_keys:
                    if key in args:
                        cap_target = (extract_host(str(args[key])) or "").lower()
                        break
                cap_target = cap_target or "*"
            else:
                cap_target = safe_path or "*"

            if session is None:
                risk.add("capability_missing",
                         f"tool {tool!r} requires capability {required_cap!r} "
                         f"but the call carries no session")
                return Decision.from_risk(
                    Verdict.DENY, rule="CAP-001", action=tool, assessment=risk,
                    reason=f"Tool {tool!r} requires capability {required_cap!r}; no session context was provided.",
                    target=target,
                    recommended_fix="Open a session (which mints the role's grants) and route calls through it.",
                    safe_path=safe_path,
                    request_id=request.request_id,
                )
            grant = session.covers(required_cap, cap_target)
            if not grant.ok:
                forged = "signature" in grant.reason or "replayed" in grant.reason
                risk.add("capability_forged" if forged else "capability_missing",
                         grant.reason)
                return Decision.from_risk(
                    Verdict.DENY,
                    rule="CAP-002" if forged else "CAP-001",
                    action=tool, assessment=risk,
                    reason=f"Capability check failed for {required_cap!r} on {cap_target!r}: {grant.reason}",
                    target=target,
                    recommended_fix=(
                        "A forged or replayed token has no legitimate origin — quarantine the session."
                        if forged else
                        "Grant the capability to the user's role in identity.rbac.roles, scoped as narrowly as the task allows."),
                    safe_path=safe_path,
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

        # 4b. v4 approval policies — the operator's "a human signs off on
        # THIS" declarations, keyed by capability or tool, optionally gated
        # on the accumulated risk score. Policies only ADD approval
        # requirements: a firing policy forces ESCALATE (APR-001), and
        # nothing here can lower a tier the operator set.
        apr = self.approval_policies.requirement(
            [required_cap if self.capabilities_enabled else "", tool],
            risk.score)
        if apr.required and tier != "escalate":
            risk.add("approval_policy", apr.why)
            return Decision.from_risk(
                Verdict.ESCALATE, rule="APR-001", action=tool, assessment=risk,
                reason=f"Approval policy requires a human decision: {apr.why}.",
                target=target, safe_path=safe_path, path_rewrites=path_rewrites,
                request_id=request.request_id,
            )

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
        downloads_cfg = self.network_cfg.get("downloads") or {}
        return {
            "inspect_response": bool(spec.get("inspect_response")),
            "redact_response": bool(self.redaction_cfg.get("enabled")),
            "inbound_inspection": bool(self.policy.get("inbound_inspection", {}).get("enabled")),
            # v3: the download guard runs for a tool when the network policy
            # enables it globally OR the tool spec opts in explicitly.
            "download_guard": bool(downloads_cfg.get("enabled") or spec.get("download_guard")),
        }
