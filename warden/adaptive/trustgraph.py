"""
warden/adaptive/trustgraph.py  (v6)

Trust graph — reason over the whole chain, not one call at a time.

Warden's per-call decisions are correct but local. The trust graph makes the
RELATIONSHIPS first-class: user -> agent -> tool -> file -> network. A single
edge can be individually fine while the PATH it completes is exactly the
injection kill chain — the agent that reads an untrusted file AND then reaches
egress has completed read-then-exfiltrate, and neither edge alone shows it.

The graph is a plain directed multigraph over typed nodes; no third-party
graph library, same stdlib-only discipline as the rest of the runtime. It
answers three questions the per-call layer structurally cannot:

  TAINT REACHABILITY (TG-001) — did data from an untrusted source reach an
  egress sink along ANY path? This is the read-then-exfiltrate detector,
  and it is a path property, invisible to any single guard.

  PRIVILEGE ISLANDS (TG-002) — is a tool reachable by a user whose role was
  never supposed to reach it, because some agent in the middle bridged two
  scopes? The v4 RBAC check is per-hop; this is the transitive closure it
  cannot see.

  BLAST RADIUS (TG-003) — if THIS node is compromised, what is reachable
  from it? Not an alarm but a quarantine-scoping tool: when something trips,
  the graph says what else to freeze.

Edges carry the audit event_id that created them, so every graph claim is
traceable back to the tamper-evident chain — the graph is a lens over the
audit log, never a second source of truth.
"""

from dataclasses import dataclass, field
from typing import Iterable


# Node types. The ordering is the trust gradient: data flows from untrusted
# sources toward sinks, and taint that reaches a sink is the thing we fear.
USER, AGENT, TOOL, FILE, NETWORK = "user", "agent", "tool", "file", "network"


@dataclass(frozen=True)
class Node:
    kind: str
    name: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Edge:
    src: Node
    dst: Node
    relation: str                 # "invokes","reads","writes","egresses", etc.
    event_id: str | None = None   # the audit record that created this edge
    tainted: bool = False         # did untrusted data flow along this edge?


@dataclass
class GraphFinding:
    rule: str
    detail: str
    path: list[str] = field(default_factory=list)


class TrustGraph:
    def __init__(self):
        self._edges: list[Edge] = []
        self._untrusted: set[Node] = set()
        self._sinks: set[Node] = set()

    # ------------------------------------------------------------------ #
    def add_edge(self, src: Node, dst: Node, relation: str,
                 event_id: str | None = None, tainted: bool = False) -> None:
        self._edges.append(Edge(src, dst, relation, event_id, tainted))

    def mark_untrusted(self, node: Node) -> None:
        """A source of data Warden does not vouch for: a file read from an
        untrusted location, a fetched web page, an inbound tool response."""
        self._untrusted.add(node)

    def mark_sink(self, node: Node) -> None:
        """A place data must not silently escape to: an egress destination."""
        self._sinks.add(node)

    def _adjacency(self) -> dict[Node, list[Edge]]:
        adj: dict[Node, list[Edge]] = {}
        for e in self._edges:
            adj.setdefault(e.src, []).append(e)
        return adj

    # ------------------------------------------------------------------ #
    def taint_paths(self) -> list[GraphFinding]:
        """TG-001: any path from an untrusted source to an egress sink.

        This is read-then-exfiltrate. Each hop may be permitted; the PATH is
        the finding. Cycle-safe (visited set), and it returns the actual
        path so the reviewer sees the chain, not just the verdict.
        """
        adj = self._adjacency()
        findings: list[GraphFinding] = []

        for source in self._untrusted:
            # DFS carrying the path; stop at the first sink reached per source
            # (one witness is enough to raise the finding).
            stack: list[tuple[Node, list[str]]] = [(source, [str(source)])]
            visited: set[Node] = set()
            while stack:
                node, path = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                if node in self._sinks and len(path) > 1:
                    findings.append(GraphFinding(
                        "TG-001",
                        f"untrusted data from {path[0]} can reach egress sink "
                        f"{str(node)} — read-then-exfiltrate path exists",
                        path=path))
                    break
                for e in adj.get(node, []):
                    stack.append((e.dst, path + [str(e.dst)]))
        return findings

    def privilege_bridges(self, allowed: dict[str, set[str]]) -> list[GraphFinding]:
        """TG-002: a user transitively reaching a tool their role never
        granted, because an agent bridged scopes.

        `allowed` maps user name -> set of tool names that user's role may
        reach directly. A reachable tool outside that set is a bridge.
        """
        adj = self._adjacency()
        findings: list[GraphFinding] = []
        for user in [n for n in self._nodes() if n.kind == USER]:
            granted = allowed.get(user.name, set())
            for tool, path in self._reachable_tools(user, adj):
                if tool.name not in granted:
                    findings.append(GraphFinding(
                        "TG-002",
                        f"user {user.name!r} can transitively reach tool "
                        f"{tool.name!r}, which their role does not grant — "
                        f"an agent in the path bridged scopes",
                        path=path))
        return findings

    def blast_radius(self, compromised: Node) -> list[str]:
        """TG-003: everything reachable from a compromised node. Not an
        alarm — the input to quarantine scoping."""
        adj = self._adjacency()
        seen: set[Node] = set()
        stack = [compromised]
        while stack:
            node = stack.pop()
            for e in adj.get(node, []):
                if e.dst not in seen:
                    seen.add(e.dst)
                    stack.append(e.dst)
        return sorted(str(n) for n in seen)

    # ------------------------------------------------------------------ #
    def _nodes(self) -> set[Node]:
        ns: set[Node] = set()
        for e in self._edges:
            ns.add(e.src)
            ns.add(e.dst)
        return ns

    def _reachable_tools(self, start: Node,
                         adj: dict[Node, list[Edge]]
                         ) -> Iterable[tuple[Node, list[str]]]:
        stack: list[tuple[Node, list[str]]] = [(start, [str(start)])]
        visited: set[Node] = set()
        while stack:
            node, path = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            if node.kind == TOOL and node != start:
                yield node, path
            for e in adj.get(node, []):
                stack.append((e.dst, path + [str(e.dst)]))
