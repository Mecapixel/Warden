"""
proxy/adaptive  (v6) — Adaptive Security.

Learn behavior, reason over relationships, simulate policy changes, and
automate response:

    behavior.py    per-agent behavioral baselines; deviations are ESCALATE
                   hints, never autonomous denies; learning is gated and
                   freezable (ANOM-001..003)
    trustgraph.py  user -> agent -> tool -> file -> network reasoning:
                   taint reachability, privilege bridges, blast radius
                   (TG-001..003)
    replay.py      replay the monitor-mode audit corpus against a candidate
                   policy; regression + coverage before rollout; read-only,
                   side-effect-free
    policy.py      adaptive context floors (tighten-only), sticky quarantine
                   (human-clear only), and intent verification against a
                   stated goal (ADAPT/QUAR/INTENT)

One discipline throughout: the adaptive layer only ever ADDS caution. Every
learned or contextual signal can raise a verdict toward restriction and route
to a human; none can lower one below the static policy floor. Learned state
never overrides a hard control — the v3 reputation-precedence lesson, applied
to everything that learns.
"""

from proxy.adaptive.behavior import (          # noqa: F401
    BehaviorBaseline, AgentProfile, Anomaly)
from proxy.adaptive.trustgraph import (        # noqa: F401
    TrustGraph, Node, Edge, GraphFinding,
    USER, AGENT, TOOL, FILE, NETWORK)
from proxy.adaptive.replay import (            # noqa: F401
    ReplayEngine, ReplayReport, ReplayDelta, simulate)
from proxy.adaptive.policy import (            # noqa: F401
    AdaptivePolicy, ContextRule, Quarantine, QuarantineRecord,
    IntentVerifier)
