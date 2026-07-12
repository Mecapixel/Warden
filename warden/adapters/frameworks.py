"""
warden/adapters/frameworks.py  (v7)

Framework-shaped entry points into WardenGate. Each function knows ONE thing:
where a given framework keeps the (tool name, callable) pair. None of them
import their framework — they duck-type against the documented tool shapes,
so Warden works with these frameworks without depending on any of them.

  guard_openai_tools(gate, tools)    OpenAI Agents SDK FunctionTool-likes
                                     (.name + .on_invoke_tool) or plain
                                     callables.
  guard_langchain_tools(gate, tools) LangChain BaseTool-likes (.name + one of
                                     ._run / .func / .invoke).
  guard_autogen_map(gate, mapping)   AutoGen function_map style
                                     ({name: callable}).
  guard_crewai_tools(gate, tools)    CrewAI tool-likes (.name + ._run or
                                     .func).

Anthropic MCP needs no adapter here: the MCP transport
(warden/transport/mcp.py, `warden run`) IS the MCP adapter, mediating any
MCP server at the protocol boundary.

Guarding is in-place-safe and non-destructive: each guard returns NEW
objects/wrappers; the originals are untouched. A tool object whose shape is
not recognized raises AdapterShapeError immediately — refusing to guard is
loud, because silently passing an unguarded tool through would be a bypass.
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Iterable

from warden.adapters.base import WardenGate


class AdapterShapeError(TypeError):
    """A tool object does not match the framework shape this adapter expects."""


def _tool_name(obj: Any) -> str:
    name = getattr(obj, "name", None) or getattr(obj, "__name__", None)
    if not name or not isinstance(name, str):
        raise AdapterShapeError(
            f"cannot determine tool name for {obj!r}; refusing to guard blindly")
    return name


# --------------------------------------------------------------------------- #
# OpenAI Agents SDK
# --------------------------------------------------------------------------- #

def guard_openai_tools(gate: WardenGate, tools: Iterable[Any]) -> list[Any]:
    """Guard OpenAI Agents SDK tools.

    Accepts FunctionTool-like objects (attributes: name, on_invoke_tool) or
    plain callables (guarded under their __name__). Returns guarded copies.
    """
    guarded: list[Any] = []
    for tool in tools:
        if callable(tool) and not hasattr(tool, "on_invoke_tool"):
            name = _tool_name(tool)
            guarded.append(gate.wrap(name, tool))
            continue
        invoke = getattr(tool, "on_invoke_tool", None)
        if invoke is None or not callable(invoke):
            raise AdapterShapeError(
                f"{tool!r} has no callable on_invoke_tool and is not callable")
        name = _tool_name(tool)
        clone = copy.copy(tool)

        def _guarded_invoke(*a: Any, _name=name, _orig=invoke, **kw: Any) -> Any:
            # SDK invokers take (context, args_json_or_dict); we mediate on the
            # tool name and pass the invocation through untouched on ALLOW.
            return gate.call(_name, lambda **args: _orig(*a, **kw),
                             _invoke_args(a, kw))
        clone.on_invoke_tool = _guarded_invoke
        guarded.append(clone)
    return guarded


def _invoke_args(a: tuple, kw: dict) -> dict:
    """Best-effort extraction of tool arguments for policy inspection.

    The SDK passes tool args as the last positional (JSON string or dict).
    Unparseable payloads are inspected as an opaque string — the policy
    engine's text normalization still sees them; nothing is hidden.
    """
    import json
    payload: Any = None
    if kw:
        payload = kw
    elif a:
        payload = a[-1]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return {"_raw": payload}
    return dict(payload) if isinstance(payload, dict) else {}


# --------------------------------------------------------------------------- #
# LangChain
# --------------------------------------------------------------------------- #

def guard_langchain_tools(gate: WardenGate, tools: Iterable[Any]) -> list[Any]:
    """Guard LangChain BaseTool-likes: .name plus one of ._run/.func/.invoke."""
    guarded: list[Any] = []
    for tool in tools:
        name = _tool_name(tool)
        clone = copy.copy(tool)
        patched = False
        for attr in ("_run", "func", "invoke"):
            orig = getattr(tool, attr, None)
            if callable(orig):
                def _g(*a: Any, _name=name, _orig=orig, **kw: Any) -> Any:
                    return gate.call(_name, lambda **args: _orig(*a, **kw),
                                     kw or ({"_args": list(a)} if a else {}))
                try:
                    setattr(clone, attr, _g)
                    patched = True
                except (AttributeError, TypeError):
                    continue
        if not patched:
            raise AdapterShapeError(
                f"{name}: no patchable _run/func/invoke found; refusing to pass unguarded")
        guarded.append(clone)
    return guarded


# --------------------------------------------------------------------------- #
# AutoGen
# --------------------------------------------------------------------------- #

def guard_autogen_map(gate: WardenGate,
                      function_map: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
    """Guard an AutoGen function_map ({tool_name: callable}). Returns a new map."""
    out: dict[str, Callable[..., Any]] = {}
    for name, fn in function_map.items():
        if not callable(fn):
            raise AdapterShapeError(f"function_map[{name!r}] is not callable")
        out[name] = gate.wrap(name, fn)
    return out


# --------------------------------------------------------------------------- #
# CrewAI
# --------------------------------------------------------------------------- #

def guard_crewai_tools(gate: WardenGate, tools: Iterable[Any]) -> list[Any]:
    """Guard CrewAI tool-likes: .name plus ._run or .func."""
    guarded: list[Any] = []
    for tool in tools:
        name = _tool_name(tool)
        clone = copy.copy(tool)
        patched = False
        for attr in ("_run", "func", "run"):
            orig = getattr(tool, attr, None)
            if callable(orig):
                def _g(*a: Any, _name=name, _orig=orig, **kw: Any) -> Any:
                    return gate.call(_name, lambda **args: _orig(*a, **kw),
                                     kw or ({"_args": list(a)} if a else {}))
                try:
                    setattr(clone, attr, _g)
                    patched = True
                except (AttributeError, TypeError):
                    continue
        if not patched:
            raise AdapterShapeError(
                f"{name}: no patchable _run/func/run found; refusing to pass unguarded")
        guarded.append(clone)
    return guarded
