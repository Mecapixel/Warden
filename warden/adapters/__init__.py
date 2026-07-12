"""
warden/adapters  (v7) — framework adapters.

One gate (WardenGate) mediating in-process tool callables through the same
Normalize -> Policy -> Approve -> Execute -> Audit pipeline the MCP transport
enforces at the protocol boundary, plus duck-typed entry points for the
OpenAI Agents SDK, LangChain, AutoGen, and CrewAI. Anthropic MCP is served
by the transport itself (`warden run`).
"""

from warden.adapters.base import WardenGate, WardenDenied            # noqa: F401
from warden.adapters.frameworks import (                             # noqa: F401
    AdapterShapeError,
    guard_openai_tools,
    guard_langchain_tools,
    guard_autogen_map,
    guard_crewai_tools,
)
