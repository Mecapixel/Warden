"""
proxy/transport/mcp.py

Real MCP transport — Warden physically between an MCP client and a live MCP
server, on the stdio transport (newline-delimited JSON-RPC 2.0).

    client (agent host)  <->  WARDEN  <->  real MCP server (subprocess)

Warden spawns the real server as a child process and relays the protocol,
intercepting exactly two things:

  REQUEST PATH  — every `tools/call` request is mediated (normalize -> policy
  -> approval -> audit) BEFORE it reaches the server. Denied calls never touch
  the server: Warden synthesizes a valid JSON-RPC tool result whose content is
  a safe, generic error (`isError: true`). The agent learns the call failed —
  not which rule, weight, or boundary stopped it (internals stay in the audit
  log, for the human).

  RESPONSE PATH — every `tools/call` RESULT is inspected before it reaches the
  agent: secret/PII redaction, then indirect-injection scanning, per policy.

Everything else (initialize, tools/list, notifications, pings) passes through
untouched: Warden is a checkpoint, not a fork of the protocol.

WATCHDOG: each forwarded call gets a deadline (`execution.timeout_seconds`,
default 30). A server that never answers gets a synthesized timeout error to
the client and an audit record — a hung tool call must not hang the runtime,
and other in-flight requests keep flowing because the relay is fully async.

FAIL CLOSED: a malformed client message that looks like a tools/call but
cannot be parsed well enough to mediate is denied, not forwarded.
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from proxy.core.mission import Mission


def parse_jsonrpc_line(line: str | bytes) -> dict | None:
    """Fail-closed parse of one newline-delimited JSON-RPC line.

    Returns a dict, or None for anything else — malformed JSON, valid JSON
    whose top level is not an object (a list/str/number has no JSON-RPC
    meaning here), pathological nesting deep enough to exhaust the parser
    (RecursionError), or undecodable bytes. The relay pumps drop None and
    keep running: a hostile peer must never be able to crash the mediator
    with a crafted line. Found and locked in by the v1.5.2 fuzz suite.
    """
    try:
        msg = json.loads(line)
    except (ValueError, RecursionError, UnicodeDecodeError):
        # ValueError covers json.JSONDecodeError; RecursionError covers
        # deep-nesting bombs like '[' * 100_000.
        return None
    return msg if isinstance(msg, dict) else None
from proxy.runtime.mediator import Mediator
from proxy.runtime.pinning import ToolRegistry, PinVerdict

DEFAULT_TOOL_TIMEOUT_SECONDS = 30


def _safe_error_result(request_id: Any, message: str) -> dict:
    """A valid MCP tool result carrying a generic error. Deliberately vague to
    the agent: rule ids, risk weights, and boundaries live in the audit log."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": f"[WARDEN] {message}"}],
            "isError": True,
        },
    }


@dataclass
class PendingCall:
    tool: str
    decision_event_id: str | None
    deadline_handle: asyncio.TimerHandle | None = None


class MCPInterceptor:
    """Protocol-level interception logic, kept free of raw I/O so it is
    directly unit-testable: feed it parsed messages, assert on what it says
    to forward, synthesize, or rewrite."""

    def __init__(self, mediator: Mediator, mission: Mission | None = None,
                 registry: "ToolRegistry | None" = None,
                 auto_approve_first_sight: bool = False):
        self.mediator = mediator
        self.mission = mission
        self.pending: dict[Any, PendingCall] = {}
        # Tool-definition pinning. When a registry is supplied, tool definitions
        # advertised by the server (tools/list) are hashed and pinned; a call to
        # a tool whose definition is unapproved or has drifted is denied at the
        # request path before it reaches the server. `blocked_tools` caches the
        # names that failed pinning so every subsequent call is denied without a
        # re-check. auto_approve_first_sight is a convenience for trusted local
        # setups (trust-on-first-use); off by default — deny-by-default.
        self.registry = registry
        self.auto_approve_first_sight = auto_approve_first_sight
        self.blocked_tools: dict[str, str] = {}   # tool -> reason
        # Request ids Warden has ALREADY answered on the server's behalf (the
        # execution watchdog fired). A real reply that arrives after that must
        # be dropped, not forwarded: forwarding it would (a) send the client a
        # second response for the same JSON-RPC id and (b) deliver tool output
        # that BYPASSES response inspection, because the call is no longer
        # pending. Entries are discarded when consumed; the set is bounded by
        # the number of timeouts in a session.
        self.dead_letters: set = set()

    # ---------------- client -> server ---------------- #
    def on_client_message(self, msg: dict) -> tuple[str, dict]:
        """Returns (action, payload):
             ("forward", original message)   — pass to the real server
             ("respond", synthesized reply)  — short-circuit back to the client
        """
        if msg.get("method") != "tools/call":
            return "forward", msg

        request_id = msg.get("id")
        params = msg.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            # Looks like a tool call but cannot be mediated -> fail closed.
            self.mediator.audit.record(
                "(malformed)", "DENY",
                "unparseable tools/call denied (fail closed)", {"rule": "FAIL-003"})
            return "respond", _safe_error_result(request_id, "Tool call was malformed and was not executed.")

        tool = params["name"]
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            args = {"_raw": args}

        # Pinning gate: a tool whose advertised definition was unapproved or
        # had drifted is denied here, before mediation ever runs.
        if tool in self.blocked_tools:
            self.mediator.audit.record(
                tool, "DENY",
                f"tool-definition pinning: {self.blocked_tools[tool]}",
                {"rule": "PIN-001"})
            return "respond", _safe_error_result(
                request_id, "This tool's definition is not approved and the call was not executed.")

        # Pinning gate, deny-by-default half: when a registry is configured,
        # a tool with NO approved pin on file may not run even if the server
        # never advertised it in tools/list. Without this check, a call issued
        # before tools/list arrives (or for a name the server never advertises)
        # would skip the pinning layer entirely — the blocked_tools cache is
        # only populated by advertisements. Registry configured means "no
        # unapproved definition runs", full stop.
        if self.registry is not None and not self.registry.is_approved(tool):
            self.mediator.audit.record(
                tool, "DENY",
                f"tool-definition pinning: tool {tool!r} has no approved pin on file "
                "(never advertised or never approved); deny by default",
                {"rule": "PIN-002"})
            return "respond", _safe_error_result(
                request_id, "This tool's definition is not approved and the call was not executed.")

        outcome = self.mediator.mediate_call(tool, args, mission=self.mission)

        if outcome.execute:
            # Enforce the canonical paths the engine checked: rewrite every
            # path-bearing argument to its resolved form before forwarding, so
            # the path that was VALIDATED and the path the server EXECUTES are
            # the same string. Without this, a server whose cwd differs from
            # workspace_root would resolve a relative path somewhere Warden
            # never checked.
            rewrites = getattr(outcome.decision, "path_rewrites", None) or {}
            arguments = params.get("arguments")
            if rewrites and isinstance(arguments, dict):
                for key, canonical in rewrites.items():
                    if key in arguments:
                        arguments[key] = canonical
            self.pending[request_id] = PendingCall(tool, outcome.decision.audit_id)
            return "forward", msg

        return "respond", _safe_error_result(
            request_id, "This tool call was not permitted and was not executed.")

    # ---------------- server -> client ---------------- #
    def on_server_message(self, msg: dict) -> dict | None:
        """Rewrites tool-call results through the response path; inspects
        tools/list advertisements for definition drift; everything else passes
        through unchanged. Returns None when the message must be DROPPED: a
        result for a call the watchdog already answered is dead-lettered, never
        forwarded — forwarding it would duplicate the JSON-RPC response AND
        hand the agent tool output that skipped response inspection."""
        request_id = msg.get("id")
        if request_id is not None and request_id in self.dead_letters and "result" in msg:
            self.dead_letters.discard(request_id)
            self.mediator.audit.record(
                "(late-reply)", "DROP",
                "server answered after the execution watchdog already synthesized a "
                "timeout for this request id; late reply dropped, never forwarded",
                {"rule": "WDG-002", "request_id": str(request_id)})
            return None

        result = msg.get("result")

        # tools/list: pin every advertised definition. This is where a server
        # reveals what its tools ARE, and therefore where a rug-pull shows up.
        if self.registry is not None and isinstance(result, dict) and isinstance(result.get("tools"), list):
            self._pin_advertised_tools(result["tools"])
            return msg

        if request_id not in self.pending or "result" not in msg:
            return msg

        call = self.pending.pop(request_id)
        content = result.get("content") if isinstance(result, dict) else None
        if not isinstance(content, list):
            return msg

        for block in content:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                safe, _notes = self.mediator.mediate_response(
                    call.tool, block["text"], parent_event_id=call.decision_event_id)
                block["text"] = safe
        return msg

    def _pin_advertised_tools(self, tools: list) -> None:
        """Check each advertised tool definition against the pinned registry,
        recording drift/first-sight and updating the blocked set. Runs once per
        tools/list; call-time checks then read the cached blocked set."""
        for tool_def in tools:
            if not isinstance(tool_def, dict):
                continue
            result = self.registry.check(tool_def)
            name = result.tool
            if result.allowed:
                self.blocked_tools.pop(name, None)
                continue
            if result.verdict == PinVerdict.UNSEEN and self.auto_approve_first_sight:
                self.registry.approve(tool_def, approved_by="trust-on-first-use")
                self.blocked_tools.pop(name, None)
                self.mediator.audit.record(
                    name, "PIN_APPROVED",
                    f"tool {name!r} auto-approved on first sight (TOFU)",
                    {"hash": result.current_hash, "version": result.version})
                continue
            self.blocked_tools[name] = result.reason
            self.mediator.audit.record(
                name,
                "PIN_DRIFT" if result.verdict == PinVerdict.DRIFTED else "PIN_UNSEEN",
                result.reason,
                {"verdict": result.verdict.value, "current_hash": result.current_hash,
                 "pinned_hash": result.pinned_hash, "version": result.version})

    def on_timeout(self, request_id: Any) -> dict | None:
        """Watchdog fired for a forwarded call. Synthesizes the client reply."""
        call = self.pending.pop(request_id, None)
        if call is None:
            return None
        # From this moment Warden has answered for this id. Any real reply the
        # server produces later is a dead letter and must be dropped on arrival.
        self.dead_letters.add(request_id)
        self.mediator.audit.record(
            call.tool, "DENY",
            "execution watchdog: server did not answer within the deadline",
            {"rule": "WDG-001"}, parent_event_id=call.decision_event_id)
        return _safe_error_result(
            request_id, "The tool did not respond in time and the call was abandoned.")


class MCPProxy:
    """The async relay: our stdin/stdout speak to the client; the spawned
    subprocess is the real MCP server."""

    def __init__(self, mediator: Mediator, server_cmd: list[str],
                 mission: Mission | None = None,
                 registry: ToolRegistry | None = None,
                 auto_approve_first_sight: bool = False,
                 sandbox=None):
        self.interceptor = MCPInterceptor(
            mediator, mission, registry=registry,
            auto_approve_first_sight=auto_approve_first_sight)
        # v5: if a ProvisionedSandbox is supplied, the REAL server runs inside
        # it — the relay spawns the sandbox argv, which contains the server
        # command. The containment posture is recorded on the audit chain
        # before the first byte of protocol flows, so every decision in the
        # run is attributable to a known isolation level.
        self.sandbox = sandbox
        self.server_cmd = list(sandbox.argv) if sandbox is not None else server_cmd
        if sandbox is not None and mediator.audit is not None:
            mediator.audit.record(
                "containment", "SANDBOX_PROVISIONED",
                f"downstream server contained at isolation "
                f"{sandbox.level!r}", sandbox.audit_detail())
        timeout = (mediator.engine.policy.get("execution", {}) or {}).get("timeout_seconds")
        self.tool_timeout = float(timeout or DEFAULT_TOOL_TIMEOUT_SECONDS)

    async def run(self) -> int:
        proc = await asyncio.create_subprocess_exec(
            *self.server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )
        loop = asyncio.get_running_loop()

        # Client stdio is read/written on worker threads via asyncio.to_thread.
        # This is portable across every event loop (notably Windows' Proactor,
        # where loop.connect_read_pipe on stdin is unsupported); the blocking
        # readline/write live off the event loop, so the relay stays async.
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        write_lock = asyncio.Lock()

        async def read_client_line() -> bytes:
            return await asyncio.to_thread(stdin.readline)

        async def to_client(payload: dict):
            data = (json.dumps(payload) + "\n").encode()

            def _write():
                stdout.write(data)
                stdout.flush()

            async with write_lock:
                await asyncio.to_thread(_write)

        async def to_server(payload: dict):
            proc.stdin.write((json.dumps(payload) + "\n").encode())
            await proc.stdin.drain()

        def arm_watchdog(request_id: Any):
            def fire():
                reply = self.interceptor.on_timeout(request_id)
                if reply is not None:
                    asyncio.create_task(to_client(reply))
            handle = loop.call_later(self.tool_timeout, fire)
            pending = self.interceptor.pending.get(request_id)
            if pending:
                pending.deadline_handle = handle

        async def pump_client():
            while True:
                line = await read_client_line()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                msg = parse_jsonrpc_line(line)
                if msg is None:
                    continue  # not a JSON-RPC object; drop, never crash
                # Mediation runs on a worker thread. The approval gate can
                # block for up to its full timeout waiting on a human at
                # /dev/tty; running it on the loop thread would freeze the
                # entire relay — including the watchdog timers, which need a
                # live loop to fire. Messages are still processed strictly in
                # order because each one is awaited before the next read.
                action, payload = await asyncio.to_thread(
                    self.interceptor.on_client_message, msg)
                if action == "forward":
                    await to_server(payload)
                    if payload.get("method") == "tools/call":
                        arm_watchdog(payload.get("id"))
                else:
                    await to_client(payload)

        async def pump_server():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                msg = parse_jsonrpc_line(line)
                if msg is None:
                    continue  # not a JSON-RPC object; drop, never crash
                request_id = msg.get("id")
                pending = self.interceptor.pending.get(request_id)
                if pending and pending.deadline_handle:
                    pending.deadline_handle.cancel()
                out = self.interceptor.on_server_message(msg)
                if out is not None:      # None => dead-lettered late reply; dropped
                    await to_client(out)

        client_task = asyncio.create_task(pump_client())
        server_task = asyncio.create_task(pump_server())
        done, pending_tasks = await asyncio.wait(
            {client_task, server_task}, return_when=asyncio.FIRST_COMPLETED)

        # Graceful drain: if the CLIENT went away first, in-flight calls that
        # were already forwarded deserve their replies (or their watchdog) —
        # tearing down early would silently drop them.
        if client_task in done and self.interceptor.pending:
            deadline = asyncio.get_running_loop().time() + self.tool_timeout + 1
            while self.interceptor.pending and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.05)

        for t in pending_tasks:
            t.cancel()
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except asyncio.TimeoutError:
                proc.kill()
        return proc.returncode or 0
