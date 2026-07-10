"""
proxy/core/request.py

Request normalization. Every action entering Warden — a tool call, a prompt to
inspect, anything — is turned into ONE Request object before any guard or policy
touches it. Everything downstream operates on this single shape, which makes the
pipeline predictable and every stage independently testable.

This is the "Normalize" step at the top of the Warden pipeline:
    Normalize -> Inspect -> Risk Score -> Policy -> Execute -> Output -> Audit
"""

import uuid
from dataclasses import dataclass, field

from proxy.core.textnorm import harden
from datetime import datetime, timezone
from typing import Any


@dataclass
class Request:
    """A single normalized action flowing through the gateway.

    tool:      the tool being invoked, e.g. "filesystem.read"
    args:      the tool arguments as a dict
    user:      the invoking user identity (for RBAC in v4; recorded now)
    metadata:  free-form context (session id, source, etc.)
    request_id: a UUID assigned at normalization so every action is traceable
    received_at: UTC timestamp of when Warden first saw it
    """
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    user: str = "anonymous"
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def normalize(cls, tool: str, args: dict[str, Any] | None = None,
                  user: str = "anonymous", metadata: dict[str, Any] | None = None) -> "Request":
        """Build a Request from raw inputs. The single entry point so every
        request is shaped and stamped identically."""
        # The tool NAME is hardened outright: a tool name is an identifier,
        # never content, so lookalike characters in it are pure obfuscation.
        # Argument VALUES are preserved for execution; inspectors receive the
        # hardened view via inspection_text().
        return cls(
            tool=harden(tool),
            args=args or {},
            user=user,
            metadata=metadata or {},
        )

    def inspection_text(self) -> str:
        """The hardened, inspection-safe join of all argument values. Every
        inspector must scan THIS, never the raw args, so zero-width and
        homoglyph obfuscation is folded away before any pattern runs."""
        return harden(" ".join(str(v) for v in self.args.values()))
