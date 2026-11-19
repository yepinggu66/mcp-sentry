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
from .ledger import AuditLedger
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

    # Track pending request IDs so we can inspect corresponding Server -> Client responses
    pending_requests: Dict[Any, Dict[str, Any]] = {}
    pending_lock = threading.Lock()
    stdout_lock = threading.Lock()

    def write_client(data: bytes):
        with stdout_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    sys.stderr.write(f"[MCP-Sentry v2.0.0] Bidirectional stdio guard active (session={session_id})\n")
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

                # 2. Inspect `tools/call` responses for Secret Redaction & Taint Tracking
                if req_meta and req_meta.get("method") == "tools/call" and "result" in msg:
                    tname = req_meta.get("tool", "unknown")
                    sanitized, redacted_rules = engine.inspect_and_redact_response(
                        tname, msg["result"], session_id=session_id, policy=cur_policy
                    )
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

                # 1. Threat Engine inspection
                verdict = engine.inspect_tool_call(
                    tool_name, tool_args, session_id=session_id, policy=cur_policy
                )
                if not verdict.allowed and verdict.action == "BLOCK":
                    sys.stderr.write(f"[MCP-Sentry BLOCKED] ({verdict.category}) {verdict.reason}\n")
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

                # 2. Circuit Breaker & Budget check
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
