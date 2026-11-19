#!/usr/bin/env python3
"""
MCP-Sentry: Zero-Overhead Circuit Breaker & Whitebox Security Proxy for Model Context Protocol (MCP)
Author: Ye Yongping (yepinggu66@gmail.com)
License: MIT
Repository: https://github.com/yepinggu66/mcp-sentry
"""

import sys
import os
import json
import time
import hashlib
import re
import argparse
import subprocess
import threading
from collections import deque
from typing import Dict, Any, Optional

VERSION = "0.1.0"

# Sensitive files and credential patterns
SECRET_PATTERNS = [
    re.compile(r"(\.env|\bshadow\b|\bid_rsa\b|\bid_ed25519\b|\bcredentials\b)", re.IGNORECASE),
    re.compile(r"(sk-proj-[a-zA-Z0-9_\-]{20,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"(ghp_[a-zA-Z0-9]{36})"),
]

# Destructive commands
DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-[rR]f\s+[\/~]", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
]

class CircuitBreaker:
    def __init__(self, max_retries: int = 3, window_seconds: float = 60.0):
        self.max_retries = max_retries
        self.window_seconds = window_seconds
        # maps call_hash -> deque of timestamps
        self.call_history: Dict[str, deque] = {}
        self.lock = threading.Lock()

    def check_and_record(self, tool_name: str, arguments: Any) -> bool:
        """Returns True if call is ALLOWED, False if CIRCUIT TRIPPED."""
        arg_str = json.dumps(arguments, sort_keys=True) if arguments else ""
        call_hash = hashlib.sha256(f"{tool_name}:{arg_str}".encode("utf-8")).hexdigest()
        now = time.time()

        with self.lock:
            if call_hash not in self.call_history:
                self.call_history[call_hash] = deque()
            
            dq = self.call_history[call_hash]
            # Prune old records
            while dq and now - dq[0] > self.window_seconds:
                dq.popleft()
            
            if len(dq) >= self.max_retries:
                return False  # Trip!
            
            dq.append(now)
            return True

class AuditLogger:
    def __init__(self, log_path: Optional[str] = None):
        if not log_path:
            home = os.path.expanduser("~")
            log_dir = os.path.join(home, ".mcp-sentry")
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "audit.log")
        self.log_path = log_path
        self.lock = threading.Lock()

    def log(self, entry: Dict[str, Any]):
        entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self.lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

def inspect_payload(tool_name: str, arguments: Any) -> Optional[str]:
    """Inspect arguments for dangerous patterns. Returns violation reason or None."""
    arg_str = json.dumps(arguments, ensure_ascii=False) if arguments else ""
    
    # 1. Check destructive patterns
    for pat in DESTRUCTIVE_PATTERNS:
        if pat.search(arg_str):
            return f"Blocked destructive command payload matching: {pat.pattern}"
            
    # 2. Check secret exfiltration patterns
    for pat in SECRET_PATTERNS:
        if pat.search(arg_str):
            return f"Blocked access to sensitive credentials/secrets matching: {pat.pattern}"

    return None

def main():
    parser = argparse.ArgumentParser(
        description="MCP-Sentry: Whitebox Security Proxy & Loop Circuit Breaker for Model Context Protocol"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--max-loop", type=int, default=3, help="Max repeated tool calls before circuit trip (default: 3)")
    parser.add_argument("--window", type=float, default=60.0, help="Sliding window in seconds (default: 60.0)")
    parser.add_argument("--audit-log", type=str, default="", help="Custom path for audit.log")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Target MCP server command to wrap (e.g. -- python server.py)")

    args = parser.parse_args()

    # Handle '--' separator
    target_cmd = args.command
    if target_cmd and target_cmd[0] == "--":
        target_cmd = target_cmd[1:]

    if not target_cmd:
        sys.stderr.write("Error: No target MCP command provided.\nUsage: mcp-sentry [options] -- <target_command> [args...]\n")
        sys.exit(1)

    circuit = CircuitBreaker(max_retries=args.max_loop, window_seconds=args.window)
    auditor = AuditLogger(log_path=args.audit_log or None)

    sys.stderr.write(f"[MCP-Sentry v{VERSION}] Guard active. Wrapping: {' '.join(target_cmd)}\n")
    sys.stderr.write(f"[MCP-Sentry] Circuit limit: {args.max_loop} identical calls / {args.window}s. Audit: {auditor.log_path}\n")

    # Spawn the target MCP child process
    try:
        proc = subprocess.Popen(
            target_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0
        )
    except Exception as e:
        sys.stderr.write(f"[MCP-Sentry FATAL] Failed to spawn child process: {e}\n")
        sys.exit(1)

    # Thread to pipe child process stdout back to parent stdout
    def relay_stdout():
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    t_out = threading.Thread(target=relay_stdout, daemon=True)
    t_out.start()

    # Main loop: intercept stdin from Client (Cursor / Claude Desktop)
    try:
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break

            # Try parsing as JSON-RPC
            try:
                msg = json.loads(line.decode("utf-8"))
            except Exception:
                # Not valid JSON or raw transport, relay transparently
                proc.stdin.write(line)
                proc.stdin.flush()
                continue

            # Check if this is a 'tools/call' request
            is_tool_call = msg.get("method") == "tools/call"
            req_id = msg.get("id")

            if is_tool_call:
                params = msg.get("params", {})
                tool_name = params.get("name", "unknown")
                tool_args = params.get("arguments", {})

                # 1. Security check
                violation = inspect_payload(tool_name, tool_args)
                if violation:
                    sys.stderr.write(f"[MCP-Sentry BLOCKED] {violation}\n")
                    auditor.log({
                        "event": "SECURITY_BLOCKED",
                        "tool": tool_name,
                        "args": tool_args,
                        "reason": violation
                    })
                    # Send JSON-RPC response directly back to client
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": f"[MCP-Sentry SECURITY INTERCEPT]: {violation}. Request aborted."
                            }],
                            "isError": True
                        }
                    }
                    resp_bytes = (json.dumps(err_resp) + "\n").encode("utf-8")
                    sys.stdout.buffer.write(resp_bytes)
                    sys.stdout.buffer.flush()
                    continue

                # 2. Circuit Breaker Loop Check
                allowed = circuit.check_and_record(tool_name, tool_args)
                if not allowed:
                    sys.stderr.write(f"[MCP-Sentry CIRCUIT TRIPPED] Loop detected on tool '{tool_name}'!\n")
                    auditor.log({
                        "event": "CIRCUIT_TRIPPED",
                        "tool": tool_name,
                        "args": tool_args,
                        "reason": f"Infinite loop detected (> {args.max_loop} identical calls in {args.window}s)"
                    })
                    # Return synthetic error to LLM to force it out of the dead loop
                    trip_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": f"[MCP-Sentry CIRCUIT BREAKER TRIPPED]: Infinite tool call loop detected (> {args.max_loop} identical calls to '{tool_name}' within {args.window}s). Tool execution halted to prevent API token/credit drain. Please revise your approach or notify the user."
                            }],
                            "isError": True
                        }
                    }
                    resp_bytes = (json.dumps(trip_resp) + "\n").encode("utf-8")
                    sys.stdout.buffer.write(resp_bytes)
                    sys.stdout.buffer.flush()
                    continue

                auditor.log({
                    "event": "TOOL_PASSED",
                    "tool": tool_name,
                    "args": tool_args
                })

            # Relay the allowed request to child
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

if __name__ == "__main__":
    main()
