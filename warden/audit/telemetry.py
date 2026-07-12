"""
warden/audit/telemetry.py  (v1.5.4)

Operational telemetry derived from the audit log. The hash-chained log exists
for forensics; this module makes the same records answer operational
questions — what is being denied, which tools carry the most risk, how often
the watchdog fires, whether injection attempts are trending — without adding
a second bookkeeping system that could disagree with the forensic record.
The log IS the source of truth; telemetry is a read-only view over it.

Usage:
    python -m warden.cli stats                # table
    python -m warden.cli stats --json         # machine-readable
    python -m warden.cli stats --top 5        # limit per-tool/rule listings

or programmatically:
    from warden.audit.telemetry import snapshot, render
    report = snapshot("audit/warden_audit.db")
"""

import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

# Decision strings appear in mixed case across writers (the mediator records
# verdict values in lowercase; the transport records DENY/DROP and pinning
# events in caps). Telemetry normalizes to lowercase buckets.
_VERDICTS = ("allow", "deny", "escalate")


def snapshot(audit_path: str) -> dict[str, Any]:
    """Aggregate the entire audit log into one operational report dict."""
    conn = sqlite3.connect(audit_path)
    try:
        rows = conn.execute(
            "SELECT ts, tool, decision, reason, detail FROM audit ORDER BY seq"
        ).fetchall()
    finally:
        conn.close()

    decisions: Counter = Counter()
    rules: Counter = Counter()
    by_tool: dict[str, Counter] = defaultdict(Counter)
    risk_by_tool: dict[str, list[float]] = defaultdict(list)
    risks: list[float] = []

    watchdog = injection = traversal = secrets = egress = 0
    pinning = Counter()

    first_ts = last_ts = None
    for ts, tool, decision, reason, detail_json in rows:
        first_ts = ts if first_ts is None else first_ts
        last_ts = ts
        d = (decision or "").lower()
        decisions[d] += 1
        tool = tool or "(none)"
        by_tool[tool][d] += 1
        by_tool[tool]["total"] += 1

        try:
            detail = json.loads(detail_json) if detail_json else {}
        except (ValueError, RecursionError):
            detail = {}

        rule = detail.get("rule")
        if rule:
            rules[rule] += 1
            fam = rule.split("-")[0]
            if fam == "WDG":
                watchdog += 1
            elif fam == "FS":
                traversal += 1
            elif fam == "SEC":
                secrets += 1
            elif fam == "EGR":
                egress += 1
            elif fam == "PIN":
                pinning[rule] += 1

        if d == "injection_signal":
            injection += 1
        if d.startswith("pin_"):
            pinning[d] += 1

        risk = detail.get("risk")
        if isinstance(risk, (int, float)):
            risks.append(float(risk))
            risk_by_tool[tool].append(float(risk))

    top_risk_tools = sorted(
        (
            {
                "tool": t,
                "avg_risk": round(sum(v) / len(v), 1),
                "max_risk": round(max(v), 1),
                "decided_calls": len(v),
            }
            for t, v in risk_by_tool.items()
        ),
        key=lambda r: (-r["avg_risk"], -r["decided_calls"]),
    )

    def _iso(ts):
        return (datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                if ts is not None else None)

    return {
        "audit_path": audit_path,
        "total_events": len(rows),
        "window": {"first": _iso(first_ts), "last": _iso(last_ts)},
        "decisions": dict(decisions),
        "verdict_counts": {v: decisions.get(v, 0) for v in _VERDICTS},
        "average_risk": round(sum(risks) / len(risks), 1) if risks else 0.0,
        "by_tool": {t: dict(c) for t, c in sorted(by_tool.items())},
        "top_risk_tools": top_risk_tools,
        "rule_frequency": dict(rules.most_common()),
        "watchdog_events": watchdog,
        "injection_detections": injection,
        "traversal_attempts": traversal,
        "secret_blocks": secrets,
        "egress_denials": egress,
        "pinning_events": dict(pinning),
    }


def render(report: dict[str, Any], top: int = 10) -> str:
    """Human-readable table for the CLI."""
    out = []
    w = report["window"]
    out.append("WARDEN AUDIT TELEMETRY")
    out.append("=" * 64)
    out.append(f"events: {report['total_events']}   "
               f"window: {w['first'] or '-'} .. {w['last'] or '-'}")
    v = report["verdict_counts"]
    out.append(f"verdicts: allow={v['allow']}  deny={v['deny']}  "
               f"escalate={v['escalate']}   avg risk={report['average_risk']}/100")
    out.append("-" * 64)
    out.append(f"watchdog timeouts     {report['watchdog_events']}")
    out.append(f"injection detections  {report['injection_detections']}")
    out.append(f"traversal attempts    {report['traversal_attempts']}")
    out.append(f"secret blocks         {report['secret_blocks']}")
    out.append(f"egress denials        {report['egress_denials']}")
    if report["pinning_events"]:
        pins = ", ".join(f"{k}={n}" for k, n in sorted(report["pinning_events"].items()))
        out.append(f"pinning               {pins}")
    out.append("-" * 64)
    out.append("highest-risk tools (by average risk of decided calls):")
    for r in report["top_risk_tools"][:top]:
        out.append(f"  {r['tool']:<28} avg {r['avg_risk']:>5}  "
                   f"max {r['max_risk']:>5}  calls {r['decided_calls']}")
    if not report["top_risk_tools"]:
        out.append("  (no risk-scored events)")
    out.append("-" * 64)
    out.append("rule frequency:")
    for rule, n in list(report["rule_frequency"].items())[:top]:
        out.append(f"  {rule:<12} {n}")
    if not report["rule_frequency"]:
        out.append("  (no rule-tagged events)")
    return "\n".join(out)
