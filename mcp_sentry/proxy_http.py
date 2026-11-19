"""
HTTP / Streamable-HTTP MCP Reverse Proxy + Live Firewall Web Dashboard + Human-in-the-Loop Approval Gate.
Zero external dependencies (built on Python stdlib ThreadingHTTPServer + urllib).
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from .circuit_breaker import CircuitBreaker
from .detectors import SchemaLockStore, ThreatEngine
from .ledger import AuditLedger
from .policy import PolicyManager


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>MCP-Sentry v2.0 — Live Zero-Trust Firewall & HITL Console</title>
<style>
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background:#0b1120; color:#e2e8f0; }
  header { display:flex; justify-content:space-between; align-items:center; padding:16px 24px; background:#0f172a; border-bottom:1px solid #1e293b; }
  .badge { padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; background:#065f46; color:#34d399; }
  .wrap { max-width:1200px; margin:24px auto; padding:0 20px; }
  .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:20px; }
  .card { background:#111827; border:1px solid #1f2937; border-radius:10px; padding:16px; }
  .kpi { font-size:26px; font-weight:800; margin-top:6px; }
  h2 { font-size:15px; color:#94a3b8; margin:20px 0 10px; text-transform:uppercase; letter-spacing:.05em; }
  table { width:100%; border-collapse:collapse; background:#111827; border:1px solid #1f2937; border-radius:10px; overflow:hidden; font-size:13px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid #1f2937; }
  th { background:#0f172a; color:#94a3b8; }
  .ALLOW { color:#34d399; font-weight:700; }
  .BLOCK { color:#f87171; font-weight:700; }
  .REDACT { color:#fbbf24; font-weight:700; }
  .PENDING { color:#60a5fa; font-weight:700; }
  button { cursor:pointer; border:none; border-radius:6px; padding:6px 12px; font-weight:700; font-size:12px; margin-right:6px; }
  .btn-ok { background:#059669; color:#fff; }
  .btn-no { background:#dc2626; color:#fff; }
</style>
</head>
<body>
<header>
  <div><strong>MCP-SENTRY v2.0</strong> <span style="color:#64748b">// Live Zero-Trust MCP Firewall &amp; Cryptographic Ledger</span></div>
  <div class="badge" id="status">LIVE GUARD ACTIVE</div>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div style="color:#94a3b8;font-size:12px">TOTAL EVENTS</div><div class="kpi" id="k-total">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:12px">BLOCKED THREATS</div><div class="kpi" style="color:#f87171" id="k-block">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:12px">PENDING HITL APPROVALS</div><div class="kpi" style="color:#60a5fa" id="k-pending">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:12px">LEDGER INTEGRITY</div><div class="kpi" style="color:#34d399;font-size:18px" id="k-chain">VERIFIED</div></div>
  </div>

  <h2>Human-in-the-Loop Approval Gate (Suspended High-Risk Calls)</h2>
  <table>
    <thead><tr><th>Approval ID</th><th>Tool</th><th>Arguments</th><th>Action</th></tr></thead>
    <tbody id="pending-body"><tr><td colspan="4" style="color:#64748b">No pending approvals.</td></tr></tbody>
  </table>

  <h2>Live Tool-Call Firewall Stream (Hash-Chained Audit Ledger)</h2>
  <table>
    <thead><tr><th>Seq</th><th>Time (UTC)</th><th>Action</th><th>Category</th><th>Tool</th><th>Reason</th><th>Latency</th><th>SHA-256</th></tr></thead>
    <tbody id="events-body"></tbody>
  </table>
</div>
<script>
async function decide(id, decision) {
  await fetch('/sentry/api/' + decision + '?id=' + encodeURIComponent(id), { method: 'POST' });
  refresh();
}
async function refresh() {
  try {
    const [evRes, penRes] = await Promise.all([
      fetch('/sentry/api/events'),
      fetch('/sentry/api/pending')
    ]);
    const ev = await evRes.json();
    const pen = await penRes.json();
    document.getElementById('k-total').textContent = ev.events.length;
    document.getElementById('k-block').textContent = ev.events.filter(x => x.action === 'BLOCK').length;
    document.getElementById('k-pending').textContent = pen.pending.length;
    document.getElementById('k-chain').textContent = ev.chain_valid ? 'CHAIN INTACT' : 'TAMPERED!';

    const pb = document.getElementById('pending-body');
    if (!pen.pending.length) {
      pb.innerHTML = '<tr><td colspan="4" style="color:#64748b">No pending high-risk tool approvals.</td></tr>';
    } else {
      pb.innerHTML = pen.pending.map(p => `
        <tr>
          <td>${p.id}</td>
          <td><strong>${p.tool}</strong></td>
          <td><code>${JSON.stringify(p.arguments).slice(0,120)}</code></td>
          <td>
            <button class="btn-ok" onclick="decide('${p.id}','approve')">APPROVE</button>
            <button class="btn-no" onclick="decide('${p.id}','deny')">DENY</button>
          </td>
        </tr>`).join('');
    }

    const eb = document.getElementById('events-body');
    eb.innerHTML = ev.events.map(e => `
      <tr>
        <td>#${e.seq}</td>
        <td>${e.timestamp}</td>
        <td class="${e.action}">${e.action}</td>
        <td>${e.category}</td>
        <td>${e.tool_name || '-'}</td>
        <td>${e.reason || '-'}</td>
        <td>${e.latency_ms}ms</td>
        <td style="color:#64748b">${(e.entry_hash||'').slice(0,10)}…</td>
      </tr>`).join('');
  } catch (err) {}
}
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""


class ApprovalQueue:
    """Thread-safe Human-in-the-Loop suspension queue for high-risk MCP tool calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}

    def request_approval(self, tool: str, arguments: Any, timeout: float) -> bool:
        aid = f"apr-{uuid.uuid4().hex[:8]}"
        ev = threading.Event()
        item = {
            "id": aid,
            "tool": tool,
            "arguments": arguments,
            "created_at": time.time(),
            "event": ev,
            "approved": False,
        }
        with self._lock:
            self._items[aid] = item
        ev.wait(timeout=timeout)
        with self._lock:
            finished = self._items.pop(aid, item)
        return bool(finished.get("approved", False))

    def decide(self, aid: str, approved: bool) -> bool:
        with self._lock:
            item = self._items.get(aid)
            if not item:
                return False
            item["approved"] = approved
            item["event"].set()
            return True

    def list_pending(self):
        with self._lock:
            return [
                {"id": k, "tool": v["tool"], "arguments": v["arguments"], "created_at": v["created_at"]}
                for k, v in self._items.items()
            ]


def run_http_proxy(
    upstream_url: str,
    host: str,
    port: int,
    policy_manager: PolicyManager,
    ledger: AuditLedger,
    lock_store: Optional[SchemaLockStore] = None,
):
    pol = policy_manager.policy
    if lock_store is None:
        lock_store = SchemaLockStore(os.path.join(ledger.log_dir, "schema_locks.json"))

    engine = ThreatEngine(policy=pol, lock_store=lock_store)
    breaker = CircuitBreaker(
        max_identical_calls=pol.max_identical_calls,
        window_seconds=pol.loop_window_seconds,
        max_session_calls=pol.max_session_calls,
        max_calls_per_minute=pol.max_calls_per_minute,
    )
    approvals = ApprovalQueue()

    class SentryHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any):
            return  # quiet default stderr logging

        def _send_json(self, code: int, obj: Dict[str, Any]):
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/sentry/ui" or self.path == "/":
                raw = DASHBOARD_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

            if self.path == "/sentry/api/events":
                valid, _, _ = ledger.verify_chain()
                self._send_json(200, {"chain_valid": valid, "events": ledger.recent_events(50)})
                return

            if self.path == "/sentry/api/pending":
                self._send_json(200, {"pending": approvals.list_pending()})
                return

            if self.path == "/sentry/health":
                self._send_json(200, {"status": "ok", "upstream": upstream_url})
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self):
            if self.path.startswith("/sentry/api/approve?id="):
                aid = self.path.split("id=", 1)[1]
                ok = approvals.decide(aid, True)
                self._send_json(200 if ok else 404, {"ok": ok, "id": aid, "decision": "APPROVED"})
                return

            if self.path.startswith("/sentry/api/deny?id="):
                aid = self.path.split("id=", 1)[1]
                ok = approvals.decide(aid, False)
                self._send_json(200 if ok else 404, {"ok": ok, "id": aid, "decision": "DENIED"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            session_id = self.headers.get("Mcp-Session-Id", self.client_address[0])
            cur_policy = policy_manager.policy
            engine.policy = cur_policy

            try:
                msg = json.loads(raw_body.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Invalid JSON-RPC payload"})
                return

            method = msg.get("method", "")
            req_id = msg.get("id")

            if method == "tools/call":
                params = msg.get("params", {}) or {}
                tool_name = str(params.get("name", "unknown"))
                tool_args = params.get("arguments", {})

                verdict = engine.inspect_tool_call(
                    tool_name, tool_args, session_id=session_id, policy=cur_policy
                )
                if not verdict.allowed and verdict.action == "BLOCK":
                    ledger.record(
                        event_type="HTTP_TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category=verdict.category,
                        severity=verdict.severity,
                        reason=verdict.reason,
                        latency_ms=verdict.latency_ms,
                        session_id=session_id,
                    )
                    self._send_json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {"type": "text", "text": f"[MCP-Sentry {verdict.category}]: {verdict.reason}"}
                                ],
                                "isError": True,
                            },
                        },
                    )
                    return

                if verdict.action == "REQUIRE_APPROVAL":
                    approved = approvals.request_approval(
                        tool_name, tool_args, timeout=cur_policy.approval_timeout_seconds
                    )
                    if not approved:
                        ledger.record(
                            event_type="HTTP_HITL_GATE",
                            action="BLOCK",
                            tool_name=tool_name,
                            category="HITL_DENIED",
                            severity="HIGH",
                            reason="Human operator denied or timed out approval request",
                            session_id=session_id,
                        )
                        self._send_json(
                            200,
                            {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [
                                        {"type": "text", "text": "[MCP-Sentry HITL GATE]: Execution denied or approval timed out."}
                                    ],
                                    "isError": True,
                                },
                            },
                        )
                        return

                bstate = breaker.check_and_record(tool_name, tool_args, session_id=session_id)
                if not bstate.allowed:
                    ledger.record(
                        event_type="HTTP_TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category="CIRCUIT_TRIPPED",
                        severity="HIGH",
                        reason=bstate.reason,
                        session_id=session_id,
                    )
                    self._send_json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": f"[MCP-Sentry CIRCUIT TRIPPED]: {bstate.reason}"}],
                                "isError": True,
                            },
                        },
                    )
                    return

                ledger.record(
                    event_type="HTTP_TOOL_CALL",
                    action="ALLOW",
                    tool_name=tool_name,
                    category="CLEAN",
                    severity="INFO",
                    latency_ms=verdict.latency_ms,
                    session_id=session_id,
                )

            # Forward to upstream MCP server
            target = upstream_url.rstrip("/") + (self.path if self.path != "/" else "")
            fwd_req = urllib.request.Request(
                target,
                data=raw_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(fwd_req, timeout=30) as resp:
                    resp_body = resp.read()
                    try:
                        resp_json = json.loads(resp_body.decode("utf-8"))
                        if method == "tools/list" and isinstance(resp_json.get("result"), dict):
                            tools = resp_json["result"].get("tools", [])
                            safe_tools, violations = engine.inspect_tools_list(tools, server_id=upstream_url)
                            for v in violations:
                                ledger.record(
                                    event_type="HTTP_TOOLS_LIST",
                                    action="BLOCK",
                                    tool_name=v.metadata.get("tool", ""),
                                    category=v.category,
                                    severity=v.severity,
                                    reason=v.reason,
                                    session_id=session_id,
                                )
                            resp_json["result"]["tools"] = safe_tools
                            resp_body = json.dumps(resp_json, ensure_ascii=False).encode("utf-8")
                        elif method == "tools/call" and "result" in resp_json:
                            tname = str((msg.get("params") or {}).get("name", "unknown"))
                            sanitized, redacted = engine.inspect_and_redact_response(
                                tname, resp_json["result"], session_id=session_id, policy=cur_policy
                            )
                            if redacted:
                                ledger.record(
                                    event_type="HTTP_RESPONSE_REDACT",
                                    action="REDACT",
                                    tool_name=tname,
                                    category="DLP_SECRET",
                                    severity="HIGH",
                                    reason=f"Redacted {', '.join(redacted)}",
                                    session_id=session_id,
                                )
                                resp_json["result"] = sanitized
                                resp_body = json.dumps(resp_json, ensure_ascii=False).encode("utf-8")
                    except Exception:
                        pass

                    self.send_response(resp.status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)
            except urllib.error.URLError as e:
                self._send_json(502, {"error": f"Upstream MCP server unreachable: {e}"})

    httpd = ThreadingHTTPServer((host, port), SentryHTTPHandler)
    print(f"[MCP-Sentry v2.0.0] HTTP/Streamable-HTTP Gateway listening on http://{host}:{port}")
    print(f"[MCP-Sentry] Live Firewall & HITL Dashboard: http://{host}:{port}/sentry/ui")
    print(f"[MCP-Sentry] Upstream MCP Server: {upstream_url}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
