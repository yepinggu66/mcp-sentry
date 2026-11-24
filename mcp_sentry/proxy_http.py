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
from .evolution import AdaptiveImmunityEngine, CanaryHoneypot, ShadowVault, TokenDietEngine
from .ledger import AuditLedger
from .license import BUYOUT_CONSOLE_URL, PAYPAL_PRO_URL, verify_license_key
from .policy import PolicyManager


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>MCP-Sentry v3.0 — Self-Evolving Firewall, Time-Machine &amp; HITL Console</title>
<style>
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background:#0b1120; color:#e2e8f0; }
  header { display:flex; justify-content:space-between; align-items:center; padding:16px 24px; background:#0f172a; border-bottom:1px solid #1e293b; }
  .badge { padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; background:#065f46; color:#34d399; }
  .paywall-bar { background:linear-gradient(90deg,#451a03,#78350f); border-bottom:1px solid #f59e0b; padding:10px 24px; display:flex; justify-content:space-between; align-items:center; font-size:12px; color:#fef3c7; }
  .paywall-bar a, .btn-act { text-decoration:none; padding:6px 12px; border-radius:6px; font-weight:800; font-size:12px; margin-left:8px; display:inline-block; cursor:pointer; border:none; }
  .wrap { max-width:1240px; margin:20px auto; padding:0 20px; }
  .grid { display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:20px; }
  .card { background:#111827; border:1px solid #1f2937; border-radius:10px; padding:14px; }
  .kpi { font-size:22px; font-weight:800; margin-top:6px; }
  h2 { font-size:14px; color:#94a3b8; margin:20px 0 10px; text-transform:uppercase; letter-spacing:.05em; display:flex; justify-content:space-between; align-items:center; }
  table { width:100%; border-collapse:collapse; background:#111827; border:1px solid #1f2937; border-radius:10px; overflow:hidden; font-size:12px; }
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
<div class="paywall-bar" id="license-bar">
  <div id="license-msg"><strong>⚠️ UNLICENSED COMMUNITY EVALUATION</strong> — Free tier caps ShadowVault at 1 file/session &amp; 3 Smart Diet compressions.</div>
  <div>
    <button class="btn-act" style="background:#f59e0b;color:#0f172a" onclick="triggerRollback()">⏪ 1-Click Time-Machine Rollback</button>
    <a href="/sentry/api/soc2.html" target="_blank" style="background:#1e293b;color:#93c5fd;border:1px solid #3b82f6">📄 Export SOC2 Audit Certificate</a>
    <a href="https://www.paypal.com/ncp/payment/7G6M6X7889A2Q" target="_blank" style="background:#10b981;color:#022c22">⚡ Unlock Pro ($49)</a>
    <a href="https://pingguye.cn/stackverdict/agentwall" target="_blank" style="background:#3b82f6;color:#fff">🏛️ Full IP Buyout ($30,000)</a>
  </div>
</div>
<header>
  <div><strong>MCP-SENTRY v3.0</strong> <span style="color:#64748b">// Self-Evolving Immunity · Time-Machine Rollback · USD Token Crusher</span></div>
  <div class="badge" id="status">LIVE GUARD ACTIVE</div>
</header>
<div class="wrap">
  <div class="grid">
    <div class="card"><div style="color:#94a3b8;font-size:11px">TOTAL EVENTS</div><div class="kpi" id="k-total">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:11px">BLOCKED THREATS</div><div class="kpi" style="color:#f87171" id="k-block">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:11px">USD SAVED (SMART DIET)</div><div class="kpi" style="color:#34d399" id="k-saved">$0.0000</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:11px">EVOLVED IMMUNITY GENES</div><div class="kpi" style="color:#c084fc" id="k-genes">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:11px">PENDING HITL APPROVALS</div><div class="kpi" style="color:#60a5fa" id="k-pending">0</div></div>
    <div class="card"><div style="color:#94a3b8;font-size:11px">LEDGER INTEGRITY</div><div class="kpi" style="color:#34d399;font-size:16px" id="k-chain">VERIFIED</div></div>
  </div>

  <h2>Human-in-the-Loop Approval Gate (Suspended High-Risk Calls)</h2>
  <table>
    <thead><tr><th>Approval ID</th><th>Tool</th><th>Triggered Policy &amp; Reason</th><th>Arguments</th><th>Action</th></tr></thead>
    <tbody id="pending-body"><tr><td colspan="5" style="color:#64748b">No pending approvals.</td></tr></tbody>
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
async function triggerRollback() {
  const res = await fetch('/sentry/api/rollback', { method: 'POST' });
  const data = await res.json();
  alert(data.message || JSON.stringify(data));
  refresh();
}
async function refresh() {
  try {
    const [evRes, penRes, evoRes] = await Promise.all([
      fetch('/sentry/api/events'),
      fetch('/sentry/api/pending'),
      fetch('/sentry/api/evolution')
    ]);
    const ev = await evRes.json();
    const pen = await penRes.json();
    const evo = await evoRes.json();
    document.getElementById('k-total').textContent = ev.events.length;
    document.getElementById('k-block').textContent = ev.events.filter(x => x.action === 'BLOCK').length;
    document.getElementById('k-pending').textContent = pen.pending.length;
    document.getElementById('k-chain').textContent = ev.chain_valid ? 'CHAIN INTACT' : 'TAMPERED!';
    document.getElementById('k-saved').textContent = '$' + (evo.cost.total_usd_saved || 0).toFixed(4);
    document.getElementById('k-genes').textContent = (evo.genes || []).length;
    if (evo.license && evo.license.is_paid) {
      document.getElementById('license-msg').innerHTML = '<strong>✅ ' + evo.license.tier + ' LICENSE ACTIVE (' + evo.license.licensee + ')</strong> — Unlimited ShadowVault Rollbacks &amp; Self-Evolving Immunity Unlocked.';
    }

    const pb = document.getElementById('pending-body');
    if (!pen.pending.length) {
      pb.innerHTML = '<tr><td colspan="5" style="color:#64748b">No pending high-risk tool approvals.</td></tr>';
    } else {
      pb.innerHTML = pen.pending.map(p => {
        const isTarget = window.location.hash === '#' + p.id;
        return `
        <tr id="${p.id}" style="${isTarget ? 'background:#1e3a5f;outline:2px solid #60a5fa;' : ''}">
          <td><code>${p.id}</code></td>
          <td><strong>${p.tool}</strong></td>
          <td>
            <span class="REDACT">[${p.severity || 'MEDIUM'}]</span>
            <code>${p.triggered_policy || 'require_approval_tools'}</code><br/>
            <span style="color:#94a3b8;font-size:12px">${p.reason || ''}</span>
          </td>
          <td><code>${JSON.stringify(p.arguments).slice(0,120)}</code></td>
          <td>
            <button class="btn-ok" onclick="decide('${p.id}','approve')">APPROVE</button>
            <button class="btn-no" onclick="decide('${p.id}','deny')">DENY</button>
          </td>
        </tr>`;
      }).join('');
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


def dispatch_approval_webhook(webhook_url: str, payload: Dict[str, Any]) -> None:
    """
    Sends a Slack/Discord/generic JSON webhook alert for a suspended HITL request.
    Includes triggered policy rule, tool arguments, and direct link to the exact request.
    """
    if not webhook_url:
        return
    summary = (
        f"[MCP-Sentry HITL Hold] Tool `{payload['tool']}` suspended by policy `{payload['triggered_policy']}` "
        f"({payload['severity']})\n"
        f"Reason: {payload['reason']}\n"
        f"Args: `{json.dumps(payload['arguments'], ensure_ascii=False)[:300]}`\n"
        f"Review exact request: {payload['review_url']}"
    )
    body = {
        "text": summary,      # Slack compatible
        "content": summary,   # Discord compatible
        "event": "mcp_sentry.hitl_approval_required",
        **payload,
    }
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=raw,
        headers={"Content-Type": "application/json", "User-Agent": "MCP-Sentry/2.1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass


class ApprovalQueue:
    """Thread-safe Human-in-the-Loop suspension queue for high-risk MCP tool calls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}

    def request_approval(
        self,
        tool: str,
        arguments: Any,
        timeout: float,
        triggered_policy: str = "require_approval_tools",
        category: str = "HITL_GATE",
        severity: str = "MEDIUM",
        reason: str = "",
        webhook_url: str = "",
        base_url: str = "http://127.0.0.1:8787",
    ) -> bool:
        aid = f"apr-{uuid.uuid4().hex[:8]}"
        ev = threading.Event()
        clean_base = base_url.rstrip("/")
        review_url = f"{clean_base}/sentry/ui#{aid}"
        item = {
            "id": aid,
            "tool": tool,
            "arguments": arguments,
            "triggered_policy": triggered_policy,
            "category": category,
            "severity": severity,
            "reason": reason,
            "review_url": review_url,
            "created_at": time.time(),
            "event": ev,
            "approved": False,
        }
        with self._lock:
            self._items[aid] = item

        if webhook_url:
            webhook_payload = {
                "approval_id": aid,
                "tool": tool,
                "arguments": arguments,
                "triggered_policy": triggered_policy,
                "category": category,
                "severity": severity,
                "reason": reason,
                "review_url": review_url,
                "approve_endpoint": f"{clean_base}/sentry/api/approve?id={aid}",
                "deny_endpoint": f"{clean_base}/sentry/api/deny?id={aid}",
            }
            threading.Thread(
                target=dispatch_approval_webhook,
                args=(webhook_url, webhook_payload),
                daemon=True,
            ).start()

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
                {
                    "id": k,
                    "tool": v["tool"],
                    "arguments": v["arguments"],
                    "triggered_policy": v.get("triggered_policy", ""),
                    "category": v.get("category", ""),
                    "severity": v.get("severity", "MEDIUM"),
                    "reason": v.get("reason", ""),
                    "created_at": v["created_at"],
                }
                for k, v in self._items.items()
            ]


def run_http_proxy(
    upstream_url: str,
    host: str,
    port: int,
    policy_manager: PolicyManager,
    ledger: AuditLedger,
    lock_store: Optional[SchemaLockStore] = None,
    webhook_url: str = "",
    public_base_url: str = "",
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
    lic = verify_license_key(pol.license_key or None)
    shadow_vault = ShadowVault(
        vault_dir=os.path.join(ledger.log_dir, "shadow_vault"),
        license_status=lic,
    )
    token_diet = TokenDietEngine(
        max_session_usd=pol.max_session_usd,
        max_response_chars=pol.max_response_chars,
        enable_payload_diet=pol.enable_payload_diet,
        license_status=lic,
    )
    immunity = AdaptiveImmunityEngine(
        genome_path=os.path.join(ledger.log_dir, "immunity_genome.json"),
        license_status=lic,
    )
    honeypot = CanaryHoneypot()
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

            if self.path == "/sentry/api/evolution":
                self._send_json(
                    200,
                    {
                        "license": {
                            "tier": lic.tier,
                            "is_paid": lic.is_paid,
                            "licensee": lic.licensee,
                            "reason": lic.reason,
                        },
                        "cost": token_diet.get_totals(),
                        "genes": immunity.list_genes(),
                        "shadow_sessions": shadow_vault.list_sessions(),
                    },
                )
                return

            if self.path == "/sentry/api/soc2.html":
                html_doc = ledger.export_soc2_html(license_status=lic).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_doc)))
                self.end_headers()
                self.wfile.write(html_doc)
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

            if self.path == "/sentry/api/rollback":
                res = shadow_vault.rollback_session()
                ledger.record(
                    event_type="SHADOW_VAULT_ROLLBACK",
                    action="ALLOW" if res.get("ok") else "BLOCK",
                    category="TIME_MACHINE_ROLLBACK",
                    severity="HIGH",
                    reason=res.get("message", ""),
                )
                self._send_json(200, res)
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

                if cur_policy.enable_canary_honeypot:
                    trapped, trap_reason = honeypot.inspect_for_canary_exfil(
                        tool_name, tool_args, session_id=session_id
                    )
                    if trapped:
                        ledger.record(
                            event_type="HTTP_TOOL_CALL",
                            action="BLOCK",
                            tool_name=tool_name,
                            category="CANARY_HONEYPOT_TRAP",
                            severity="CRITICAL",
                            reason=trap_reason,
                            session_id=session_id,
                        )
                        self._send_json(
                            200,
                            {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": f"[MCP-Sentry HONEYPOT TRAP]: {trap_reason}"}],
                                    "isError": True,
                                },
                            },
                        )
                        return

                if cur_policy.enable_adaptive_immunity:
                    matched_gene = immunity.inspect_call(tool_name, tool_args)
                    if matched_gene is not None:
                        reason = f"Blocked by Self-Evolving Immunity Gene {matched_gene.gene_id} ({matched_gene.category})"
                        ledger.record(
                            event_type="HTTP_TOOL_CALL",
                            action="BLOCK",
                            tool_name=tool_name,
                            category=matched_gene.category,
                            severity=matched_gene.severity,
                            reason=reason,
                            session_id=session_id,
                        )
                        self._send_json(
                            200,
                            {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": f"[MCP-Sentry ADAPTIVE IMMUNITY]: {reason}"}],
                                    "isError": True,
                                },
                            },
                        )
                        return

                verdict = engine.inspect_tool_call(
                    tool_name, tool_args, session_id=session_id, policy=cur_policy
                )
                if not verdict.allowed and verdict.action == "BLOCK":
                    if cur_policy.enable_adaptive_immunity:
                        immunity.evolve_from_incident(tool_name, tool_args, verdict.category, verdict.severity)
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
                    active_webhook = webhook_url or cur_policy.approval_webhook_url
                    active_base = public_base_url or cur_policy.public_base_url or f"http://{host}:{port}"
                    approved = approvals.request_approval(
                        tool_name,
                        tool_args,
                        timeout=cur_policy.approval_timeout_seconds,
                        triggered_policy=verdict.matched_rule or "require_approval_tools",
                        category=verdict.category,
                        severity=verdict.severity,
                        reason=verdict.reason,
                        webhook_url=active_webhook,
                        base_url=active_base,
                    )
                    if not approved:
                        if cur_policy.enable_adaptive_immunity:
                            immunity.evolve_from_incident(tool_name, tool_args, "HITL_DENIED", "HIGH")
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

                usd_state = token_diet.check_and_account_request(tool_name, tool_args, session_id=session_id)
                if not usd_state.allowed:
                    ledger.record(
                        event_type="HTTP_TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category="USD_BUDGET_TRIPPED",
                        severity="HIGH",
                        reason=usd_state.reason,
                        session_id=session_id,
                    )
                    self._send_json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": f"[MCP-Sentry USD BUDGET BREAKER]: {usd_state.reason}"}],
                                "isError": True,
                            },
                        },
                    )
                    return

                if cur_policy.enable_shadow_vault:
                    shadow_vault.snapshot_before_call(tool_name, tool_args, session_id=session_id)

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
                            compressed_res, diet_metrics = token_diet.inspect_and_compress_response(
                                tname, resp_json["result"], session_id=session_id
                            )
                            if diet_metrics.diet_applied:
                                resp_json["result"] = compressed_res
                            if redacted or diet_metrics.diet_applied:
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
    print(f"[MCP-Sentry v3.0.0] HTTP/Streamable-HTTP Gateway listening on http://{host}:{port} (Tier: {lic.tier})")
    print(f"[MCP-Sentry] Live Firewall, Time-Machine & HITL Console: http://{host}:{port}/sentry/ui")
    print(f"[MCP-Sentry] SOC2 / EU AI Act Certificate Endpoint: http://{host}:{port}/sentry/api/soc2.html")
    print(f"[MCP-Sentry] Upstream MCP Server: {upstream_url}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
