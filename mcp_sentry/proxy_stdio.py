"""
Bidirectional JSON-RPC 2.0 stdio Interceptor for MCP Clients (Cursor, Claude Desktop, Windsurf, Claude Code).

Intercepts BOTH directions:
  - Client -> Server: Policy enforcement, Destructive/Path-Traversal/DLP/Taint checks, Circuit Breaker.
  - Server -> Client: Tool Poisoning & Rug-Pull Schema Lock on `tools/list`, Secret Redaction & Tainting on `tools/call` responses.
"""

import json
import os
import subprocess
import sys
import threading
import uuid
from typing import Any, Dict, List, Optional

from .circuit_breaker import CircuitBreaker
from .detectors import SchemaLockStore, ThreatEngine
from .evolution import AdaptiveImmunityEngine, CanaryHoneypot, ShadowVault, TokenDietEngine
from .ledger import AuditLedger
from .license import verify_license_key
from .policy import PolicyManager


def _jsonrpc_error_result(req_id: Any, message: str) -> bytes:
    payload = {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        },
    }
    return (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")


def run_stdio_proxy(
    target_cmd: List[str],
    policy_manager: PolicyManager,
    ledger: AuditLedger,
    lock_store: Optional[SchemaLockStore] = None,
    server_id: str = "",
) -> int:
    pol = policy_manager.policy
    sid = server_id or " ".join(target_cmd[:2])
    session_id = f"stdio-{uuid.uuid4().hex[:8]}"

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
    honeypot.mint_canary_env(session_id=session_id)

    # Track pending request IDs so we can inspect corresponding Server -> Client responses
    pending_requests: Dict[Any, Dict[str, Any]] = {}
    pending_lock = threading.Lock()
    stdout_lock = threading.Lock()

    def write_client(data: bytes):
        with stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    sys.stderr.write(
        f"[MCP-Sentry v3.0.0] Bidirectional stdio guard active (session={session_id}, tier={lic.tier})\n"
    )
    sys.stderr.write(f"[MCP-Sentry] Wrapping: {' '.join(target_cmd)}\n")
    sys.stderr.write(f"[MCP-Sentry] Audit ledger: {ledger.jsonl_path}\n")

    try:
        proc = subprocess.Popen(
            target_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
        )
    except Exception as e:
        sys.stderr.write(f"[MCP-Sentry FATAL] Failed to spawn MCP server: {e}\n")
        return 1

    def relay_server_to_client():
        assert proc.stdout is not None
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode("utf-8"))
                except Exception:
                    write_client(line)
                    continue

                resp_id = msg.get("id")
                req_meta = None
                if resp_id is not None:
                    with pending_lock:
                        req_meta = pending_requests.pop(resp_id, None)

                cur_policy = policy_manager.policy
                engine.policy = cur_policy

                # 0. Track mid-session dynamic tool list mutations (`notifications/tools/list_changed`)
                if msg.get("method") == "notifications/tools/list_changed":
                    sys.stderr.write("[MCP-Sentry NOTICE] Server emitted notifications/tools/list_changed; next tools/list will be re-scanned & verified against SHA-256 schema locks.\n")
                    ledger.record(
                        event_type="TOOLS_LIST_CHANGED",
                        action="ALLOW",
                        category="SCHEMA_WATCH",
                        severity="MEDIUM",
                        reason="Server notified mid-session tools/list_changed; re-verification armed",
                        session_id=session_id,
                    )

                # 1. Inspect `tools/list` responses for Tool Poisoning & Rug-Pull
                if req_meta and req_meta.get("method") == "tools/list" and isinstance(msg.get("result"), dict):
                    tools = msg["result"].get("tools")
                    if isinstance(tools, list):
                        safe_tools, violations = engine.inspect_tools_list(tools, server_id=sid)
                        for v in violations:
                            sys.stderr.write(f"[MCP-Sentry {v.category}] {v.reason}\n")
                            ledger.record(
                                event_type="TOOLS_LIST_INSPECT",
                                action="BLOCK",
                                tool_name=v.metadata.get("tool", ""),
                                category=v.category,
                                severity=v.severity,
                                reason=v.reason,
                                latency_ms=v.latency_ms,
                                session_id=session_id,
                                payload=v.metadata,
                            )
                        if violations:
                            msg["result"]["tools"] = safe_tools
                            write_client((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
                            continue

                # 2. Inspect `tools/call` responses for Secret Redaction, Taint Tracking & Smart Payload Diet
                if req_meta and req_meta.get("method") == "tools/call" and "result" in msg:
                    tname = req_meta.get("tool", "unknown")
                    sanitized, redacted_rules = engine.inspect_and_redact_response(
                        tname, msg["result"], session_id=session_id, policy=cur_policy
                    )
                    modified_resp = False
                    if redacted_rules:
                        sys.stderr.write(
                            f"[MCP-Sentry REDACTED] Scrubbed {redacted_rules} from '{tname}' output & tainted session\n"
                        )
                        ledger.record(
                            event_type="RESPONSE_REDACT",
                            action="REDACT",
                            tool_name=tname,
                            category="DLP_SECRET",
                            severity="HIGH",
                            reason=f"Redacted secrets from tool output: {', '.join(redacted_rules)}",
                            session_id=session_id,
                            payload={"rules": redacted_rules},
                        )
                        msg["result"] = sanitized
                        modified_resp = True

                    compressed_res, diet_metrics = token_diet.inspect_and_compress_response(
                        tname, msg["result"], session_id=session_id
                    )
                    if diet_metrics.diet_applied:
                        sys.stderr.write(
                            f"[MCP-Sentry SMART DIET] Compressed bloated '{tname}' output (Total saved: ${diet_metrics.session_usd_saved:.4f} USD)\n"
                        )
                        msg["result"] = compressed_res
                        modified_resp = True
                    if diet_metrics.commercial_notice:
                        sys.stderr.write(f"{diet_metrics.commercial_notice}\n")

                    if modified_resp:
                        write_client((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
                        continue

                write_client(line)
        except Exception:
            pass

    t_out = threading.Thread(target=relay_server_to_client, daemon=True)
    t_out.start()

    assert proc.stdin is not None
    try:
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break

            try:
                msg = json.loads(line.decode("utf-8"))
            except Exception:
                proc.stdin.write(line)
                proc.stdin.flush()
                continue

            method = msg.get("method", "")
            req_id = msg.get("id")
            cur_policy = policy_manager.policy
            engine.policy = cur_policy

            if method == "tools/list" and req_id is not None:
                with pending_lock:
                    pending_requests[req_id] = {"method": "tools/list"}
                proc.stdin.write(line)
                proc.stdin.flush()
                continue

            if method == "tools/call":
                params = msg.get("params", {}) or {}
                tool_name = str(params.get("name", "unknown"))
                tool_args = params.get("arguments", {})

                # 0a. Active Canary Honeypot trap check
                if cur_policy.enable_canary_honeypot:
                    trapped, trap_reason = honeypot.inspect_for_canary_exfil(
                        tool_name, tool_args, session_id=session_id
                    )
                    if trapped:
                        sys.stderr.write(f"[MCP-Sentry HONEYPOT TRAP] {trap_reason}\n")
                        ledger.record(
                            event_type="TOOL_CALL",
                            action="BLOCK",
                            tool_name=tool_name,
                            category="CANARY_HONEYPOT_TRAP",
                            severity="CRITICAL",
                            reason=trap_reason,
                            session_id=session_id,
                        )
                        write_client(
                            _jsonrpc_error_result(req_id, f"[MCP-Sentry CANARY HONEYPOT TRAP]: {trap_reason}")
                        )
                        continue

                # 0b. Self-Evolving Adaptive Immunity check
                if cur_policy.enable_adaptive_immunity:
                    matched_gene = immunity.inspect_call(tool_name, tool_args)
                    if matched_gene is not None:
                        reason = f"Blocked by Self-Evolving Immunity Gene {matched_gene.gene_id} ({matched_gene.category})"
                        sys.stderr.write(f"[MCP-Sentry IMMUNITY BLOCK] {reason}\n")
                        ledger.record(
                            event_type="TOOL_CALL",
                            action="BLOCK",
                            tool_name=tool_name,
                            category=matched_gene.category,
                            severity=matched_gene.severity,
                            reason=reason,
                            session_id=session_id,
                            payload={"gene_id": matched_gene.gene_id},
                        )
                        write_client(_jsonrpc_error_result(req_id, f"[MCP-Sentry ADAPTIVE IMMUNITY]: {reason}"))
                        continue

                # 1. Threat Engine inspection
                verdict = engine.inspect_tool_call(
                    tool_name, tool_args, session_id=session_id, policy=cur_policy
                )
                if not verdict.allowed and verdict.action == "BLOCK":
                    sys.stderr.write(f"[MCP-Sentry BLOCKED] ({verdict.category}) {verdict.reason}\n")
                    if cur_policy.enable_adaptive_immunity:
                        gene, evo_notice = immunity.evolve_from_incident(
                            tool_name, tool_args, verdict.category, verdict.severity
                        )
                        if evo_notice:
                            sys.stderr.write(f"{evo_notice}\n")
                    ledger.record(
                        event_type="TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category=verdict.category,
                        severity=verdict.severity,
                        reason=verdict.reason,
                        latency_ms=verdict.latency_ms,
                        session_id=session_id,
                        payload={"rule": verdict.matched_rule},
                    )
                    write_client(
                        _jsonrpc_error_result(
                            req_id,
                            f"[MCP-Sentry {verdict.category} INTERCEPT]: {verdict.reason}. Request aborted.",
                        )
                    )
                    continue

                # 2. Circuit Breaker & USD Token Budget check
                bstate = breaker.check_and_record(tool_name, tool_args, session_id=session_id)
                if not bstate.allowed:
                    sys.stderr.write(f"[MCP-Sentry CIRCUIT TRIPPED] {bstate.reason}\n")
                    ledger.record(
                        event_type="TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category="CIRCUIT_TRIPPED",
                        severity="HIGH",
                        reason=bstate.reason,
                        session_id=session_id,
                        payload={"session_calls": bstate.session_calls},
                    )
                    write_client(
                        _jsonrpc_error_result(
                            req_id,
                            f"[MCP-Sentry CIRCUIT BREAKER TRIPPED]: {bstate.reason}. Execution halted to protect API budget.",
                        )
                    )
                    continue

                usd_state = token_diet.check_and_account_request(tool_name, tool_args, session_id=session_id)
                if not usd_state.allowed:
                    sys.stderr.write(f"[MCP-Sentry USD BUDGET TRIPPED] {usd_state.reason}\n")
                    ledger.record(
                        event_type="TOOL_CALL",
                        action="BLOCK",
                        tool_name=tool_name,
                        category="USD_BUDGET_TRIPPED",
                        severity="HIGH",
                        reason=usd_state.reason,
                        session_id=session_id,
                    )
                    write_client(_jsonrpc_error_result(req_id, f"[MCP-Sentry USD BUDGET BREAKER]: {usd_state.reason}"))
                    continue

                # 3. Pre-execution ShadowVault Time-Machine snapshot for mutating tools
                if cur_policy.enable_shadow_vault:
                    snaps, snap_notice = shadow_vault.snapshot_before_call(
                        tool_name, tool_args, session_id=session_id
                    )
                    if snaps:
                        sys.stderr.write(
                            f"[MCP-Sentry ShadowVault] Snapshotted {len(snaps)} file(s) before '{tool_name}' (Rollback ready: `mcp-sentry rollback --session {session_id}`)\n"
                        )
                    if snap_notice:
                        sys.stderr.write(f"{snap_notice}\n")

                ledger.record(
                    event_type="TOOL_CALL",
                    action="ALLOW",
                    tool_name=tool_name,
                    category="CLEAN",
                    severity="INFO",
                    latency_ms=verdict.latency_ms,
                    session_id=session_id,
                )

                if req_id is not None:
                    with pending_lock:
                        pending_requests[req_id] = {"method": "tools/call", "tool": tool_name}

            proc.stdin.write(line)
            proc.stdin.flush()

    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass

    return 0
