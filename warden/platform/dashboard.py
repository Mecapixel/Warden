"""
warden/platform/dashboard.py  (v7)

The Warden dashboard — logs, metrics, sessions, policy, and replay, served
locally. This is also the desktop app's engine: `warden desktop` opens the
same server in a native window (pywebview, optional) or the default browser.

Security posture, because a security tool's own dashboard is an attack
surface:

  LOCALHOST ONLY.   The server binds 127.0.0.1. There is no flag to bind
                    0.0.0.0 — exposing the audit trail to a network is a
                    reverse-proxy-with-auth decision a human makes outside
                    this tool, never a default it drifts into.
  TOKEN REQUIRED.   A per-run random token (secrets.token_urlsafe) is minted
                    at startup and required on every request (X-Warden-Token
                    header or ?token=). Compared with hmac.compare_digest.
                    This stops other local processes and drive-by browser
                    requests from reading the audit trail.
  READ-ONLY OVER STATE. The dashboard never writes the audit chain, never
                    edits the live policy, never executes a tool. Its two
                    POST endpoints (validate, replay) evaluate CANDIDATE
                    policy text in memory and report — the same read-only
                    contract as the v6 replay engine, exposed over HTTP.
  STDLIB ONLY.      http.server + sqlite3 + json. A dashboard that added a
                    web framework to a runtime that is deliberately
                    stdlib+PyYAML would invert the project's own supply-chain
                    posture.
"""

from __future__ import annotations

import hmac
import json
import secrets
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from warden import __version__
from warden.audit.log import AuditLog
from warden.audit.telemetry import snapshot

_HOST = "127.0.0.1"          # not configurable, by design
_MAX_BODY = 2 * 1024 * 1024  # candidate policy YAML; nothing legitimate is bigger


# --------------------------------------------------------------------------- #

class DashboardServer:
    """Owns the HTTP server, the auth token, and the read paths."""

    def __init__(self, policy_path: str | Path, audit_path: str | Path,
                 port: int = 0, token: str | None = None):
        self.policy_path = Path(policy_path)
        self.audit_path = Path(audit_path)
        self.token = token or secrets.token_urlsafe(24)
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer((_HOST, port), handler)
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{_HOST}:{self.port}/?token={self.token}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    # ------------------------------------------------------------------ #
    # data providers (each opens read-only and closes; no long-lived handles)

    def api_health(self) -> dict[str, Any]:
        return {"ok": True, "version": __version__,
                "policy": str(self.policy_path), "audit": str(self.audit_path)}

    def api_telemetry(self) -> dict[str, Any]:
        if not self.audit_path.exists():
            return {"empty": True, "reason": "no audit log yet"}
        return snapshot(str(self.audit_path))

    def api_audit(self, limit: int = 200) -> dict[str, Any]:
        if not self.audit_path.exists():
            return {"records": [], "chain": {"ok": True, "note": "no audit log yet"}}
        log = AuditLog(str(self.audit_path))
        try:
            records = log.records()[-int(limit):]
            for r in records:
                try:
                    r["detail"] = json.loads(r.get("detail") or "{}")
                except (ValueError, TypeError):
                    pass
            chain = log.verify_chain_detail()
        finally:
            log.close()
        return {"records": records, "chain": chain}

    def api_sessions(self) -> dict[str, Any]:
        """Aggregate the audit trail by user and session for inspection."""
        if not self.audit_path.exists():
            return {"sessions": []}
        log = AuditLog(str(self.audit_path))
        try:
            recs = log.records()
        finally:
            log.close()
        agg: dict[str, dict[str, Any]] = {}
        for r in recs:
            try:
                detail = json.loads(r.get("detail") or "{}")
            except (ValueError, TypeError):
                detail = {}
            key = str(detail.get("session") or detail.get("user") or "anonymous")
            row = agg.setdefault(key, {"principal": key, "calls": 0,
                                       "denied": 0, "escalated": 0,
                                       "tools": set(), "first_ts": r["ts"],
                                       "last_ts": r["ts"]})
            row["calls"] += 1
            d = (r.get("decision") or "").upper()
            if d == "DENY":
                row["denied"] += 1
            if d == "ESCALATE":
                row["escalated"] += 1
            row["tools"].add(r.get("tool") or "(none)")
            row["last_ts"] = r["ts"]
        out = []
        for row in agg.values():
            row["tools"] = sorted(row["tools"])
            out.append(row)
        return {"sessions": sorted(out, key=lambda r: -r["last_ts"])}

    def api_policy(self) -> dict[str, Any]:
        from warden.policy.engine import PolicyEngine, PolicyValidationError
        text = self.policy_path.read_text() if self.policy_path.exists() else ""
        status: dict[str, Any] = {"path": str(self.policy_path), "text": text}
        try:
            PolicyEngine(str(self.policy_path))
            status["valid"] = True
        except (PolicyValidationError, FileNotFoundError, OSError) as e:
            status["valid"] = False
            status["error"] = str(e)
        return status

    def api_validate(self, candidate_yaml: str) -> dict[str, Any]:
        """Validate CANDIDATE policy text. In memory; live policy untouched."""
        from warden.policy.engine import PolicyEngine, PolicyValidationError
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(candidate_yaml)
            tmp = f.name
        try:
            PolicyEngine(tmp)
            return {"valid": True}
        except PolicyValidationError as e:
            return {"valid": False, "error": str(e)}
        finally:
            Path(tmp).unlink(missing_ok=True)

    def api_replay(self, candidate_yaml: str) -> dict[str, Any]:
        """Replay the recorded corpus against candidate policy text (v6 engine).

        Read-only and side-effect-free, same as `simulate` itself: nothing is
        executed, nothing is written, the live policy is untouched.
        """
        from warden.adaptive.replay import ReplayEngine
        from warden.policy.engine import PolicyEngine, PolicyValidationError
        if not self.audit_path.exists():
            return {"error": "no audit corpus to replay"}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(candidate_yaml)
            tmp = f.name
        try:
            try:
                engine = PolicyEngine(tmp)
            except PolicyValidationError as e:
                return {"error": f"candidate policy invalid: {e}"}
            log = AuditLog(str(self.audit_path))
            try:
                records = log.records()
            finally:
                log.close()
            report = ReplayEngine(engine).replay(records)
            deltas = (report.newly_stricter + report.newly_looser)[:200]
            return {
                "total": report.total,
                "replayable": report.replayable,
                "skipped": report.skipped,
                "unchanged": report.unchanged,
                "would_break_count": report.would_break_count,
                "deltas": [
                    {"tool": d.tool, "args": d.args_summary,
                     "recorded": d.recorded_verdict,
                     "candidate": d.candidate_verdict,
                     "rule": d.candidate_rule, "direction": d.direction}
                    for d in deltas
                ],
                "summary": report.summary(),
            }
        finally:
            Path(tmp).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #

def _make_handler(server: DashboardServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"WardenDashboard/{__version__}"

        # -- auth ------------------------------------------------------- #
        def _authed(self) -> bool:
            supplied = self.headers.get("X-Warden-Token", "")
            if not supplied:
                q = parse_qs(urlparse(self.path).query)
                supplied = (q.get("token") or [""])[0]
            return hmac.compare_digest(supplied, server.token)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # the page is same-origin-only; belt-and-suspenders headers:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: Any, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode(),
                       "application/json")

        # -- routes ----------------------------------------------------- #
        def do_GET(self) -> None:                                  # noqa: N802
            if not self._authed():
                self._json({"error": "missing or invalid token"}, 401)
                return
            route = urlparse(self.path).path
            q = parse_qs(urlparse(self.path).query)
            if route == "/":
                self._send(200, _page(server).encode(), "text/html; charset=utf-8")
            elif route == "/api/health":
                self._json(server.api_health())
            elif route == "/api/telemetry":
                self._json(server.api_telemetry())
            elif route == "/api/audit":
                limit = int((q.get("limit") or ["200"])[0])
                self._json(server.api_audit(limit=limit))
            elif route == "/api/sessions":
                self._json(server.api_sessions())
            elif route == "/api/policy":
                self._json(server.api_policy())
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:                                 # noqa: N802
            # Read the request body BEFORE deciding anything, including auth.
            # Responding while the client is still sending makes Windows
            # abort the connection (WinError 10053), turning every rejected
            # request into a client-side socket error instead of a clean 401.
            # The read is bounded so draining can't be weaponized.
            length = int(self.headers.get("Content-Length") or 0)
            if length > _MAX_BODY:
                _ = self.rfile.read(_MAX_BODY)          # drain what we accept
                self._json({"error": "body too large"}, 413)
                return
            body = self.rfile.read(length).decode("utf-8", "replace")
            if not self._authed():
                self._json({"error": "missing or invalid token"}, 401)
                return
            route = urlparse(self.path).path
            if route == "/api/policy/validate":
                self._json(server.api_validate(body))
            elif route == "/api/replay":
                self._json(server.api_replay(body))
            else:
                self._json({"error": "not found"}, 404)

        def log_message(self, fmt: str, *args: Any) -> None:
            pass                                    # quiet; audit is elsewhere

    return Handler


# --------------------------------------------------------------------------- #
# The page. One file, no CDN, no external requests — the dashboard makes the
# same supply-chain promise as the runtime.
# --------------------------------------------------------------------------- #

def _page(server: DashboardServer) -> str:
    return """<!doctype html>
<html><head><meta charset="utf-8"><title>Warden</title>
<style>
 body{font-family:ui-monospace,Consolas,monospace;background:#0d1117;color:#c9d1d9;
      margin:0;padding:1.2rem}
 h1{font-size:1.1rem;color:#58a6ff} h2{font-size:.95rem;color:#8b949e;margin:1.4rem 0 .4rem}
 table{border-collapse:collapse;width:100%;font-size:.8rem}
 td,th{border-bottom:1px solid #21262d;padding:.25rem .5rem;text-align:left}
 .DENY{color:#f85149}.ALLOW{color:#3fb950}.ESCALATE{color:#d29922}
 .REDACT{color:#58a6ff}.APPROVED{color:#3fb950}.REFUSED{color:#f85149}
 textarea{width:100%;height:9rem;background:#161b22;color:#c9d1d9;
      border:1px solid #30363d;font-family:inherit}
 button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;
      padding:.3rem .8rem;cursor:pointer}
 pre{background:#161b22;padding:.6rem;overflow:auto;font-size:.75rem}
 .pill{display:inline-block;padding:.1rem .5rem;border:1px solid #30363d;
      border-radius:1rem;margin-right:.4rem;font-size:.75rem}
</style></head><body>
<h1>Warden dashboard</h1>
<div id="meta"></div>
<h2>Telemetry</h2><div id="tele"></div>
<h2>Sessions</h2><table id="sess"></table>
<h2>Recent decisions <span id="chain" class="pill"></span></h2>
<table id="audit"></table>
<h2>Policy (live, read-only)</h2><pre id="policy"></pre>
<h2>Candidate policy — validate &amp; replay (in-memory, live policy untouched)</h2>
<textarea id="cand" placeholder="paste candidate policy YAML"></textarea><br>
<button onclick="validateCand()">Validate</button>
<button onclick="replayCand()">Replay against recorded corpus</button>
<pre id="result"></pre>
<script>
const T = new URLSearchParams(location.search).get('token');
const H = {'X-Warden-Token': T};
const j = (u,o) => fetch(u,Object.assign({headers:H},o)).then(r=>r.json());
function esc(s){return String(s).replace(/[&<>"]/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function load(){
  const h = await j('/api/health');
  document.getElementById('meta').innerHTML =
    `<span class=pill>v${esc(h.version)}</span><span class=pill>policy: ${esc(h.policy)}</span>`+
    `<span class=pill>audit: ${esc(h.audit)}</span>`;
  const t = await j('/api/telemetry');
  document.getElementById('tele').innerHTML =
    t.empty ? '(no audit corpus yet)' :
    Object.entries(t.decisions||{}).map(([k,v])=>
      `<span class="pill ${esc(k.toUpperCase())}">${esc(k)}: ${v}</span>`).join('');
  const s = await j('/api/sessions');
  document.getElementById('sess').innerHTML =
    '<tr><th>principal</th><th>calls</th><th>denied</th><th>escalated</th><th>tools</th></tr>'+
    (s.sessions||[]).map(r=>`<tr><td>${esc(r.principal)}</td><td>${r.calls}</td>`+
      `<td>${r.denied}</td><td>${r.escalated}</td><td>${esc(r.tools.join(', '))}</td></tr>`).join('');
  const a = await j('/api/audit?limit=100');
  document.getElementById('chain').textContent =
    a.chain && a.chain.ok!==false ? 'chain: verified' : 'chain: BROKEN';
  document.getElementById('audit').innerHTML =
    '<tr><th>ts</th><th>tool</th><th>decision</th><th>reason</th></tr>'+
    (a.records||[]).slice().reverse().map(r=>
      `<tr><td>${new Date(r.ts*1000).toISOString()}</td><td>${esc(r.tool)}</td>`+
      `<td class="${esc(r.decision)}">${esc(r.decision)}</td><td>${esc(r.reason)}</td></tr>`).join('');
  const p = await j('/api/policy');
  document.getElementById('policy').textContent =
    (p.valid?'# VALID\\n':'# INVALID: '+(p.error||'')+'\\n')+p.text;
}
async function validateCand(){
  const r = await j('/api/policy/validate',{method:'POST',
    body:document.getElementById('cand').value});
  document.getElementById('result').textContent = JSON.stringify(r,null,2);
}
async function replayCand(){
  const r = await j('/api/replay',{method:'POST',
    body:document.getElementById('cand').value});
  document.getElementById('result').textContent =
    r.error ? r.error : r.summary + '\\n\\n' + JSON.stringify(r.deltas,null,2);
}
load();
</script></body></html>"""


# --------------------------------------------------------------------------- #

def open_desktop(server: DashboardServer) -> None:
    """`warden desktop` — the dashboard in a native window when pywebview is
    installed (`pip install warden-security[desktop]`), else the default
    browser. Either way it is the same localhost server, same token."""
    try:
        import webview                                   # type: ignore
        window = webview.create_window(f"Warden {__version__}", server.url)
        webview.start()
        _ = window
    except ImportError:
        import webbrowser
        webbrowser.open(server.url)
