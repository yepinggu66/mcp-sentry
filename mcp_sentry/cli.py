"""
MCP-Sentry v2.0.0 CLI entrypoint.
Supports:
  - `mcp-sentry wrap [options] -- <target_mcp_command>` (also backwards-compatible `mcp-sentry -- <cmd>`)
  - `mcp-sentry proxy --upstream <url> --port 8787`
  - `mcp-sentry bench`
  - `mcp-sentry audit --verify`
  - `mcp-sentry init`
"""

import argparse
import os
import sys

from . import VERSION
from .benchmark import run_benchmark
from .ledger import AuditLedger
from .policy import PolicyManager, SentryPolicy
from .proxy_http import run_http_proxy
from .proxy_stdio import run_stdio_proxy


DEFAULT_SENTRY_YAML = """# MCP-Sentry v2.0 Policy-as-Code Configuration (Hot-Reloaded Automatically)
max_identical_calls: 3
loop_window_seconds: 60.0
max_session_calls: 200
max_calls_per_minute: 60

block_tool_poisoning: true
block_rug_pull: true
block_destructive_commands: true
block_secret_exfiltration: true
enable_taint_tracking: true
redact_response_secrets: true
enable_entropy_scan: true
entropy_threshold: 4.6

# High-risk tools that require Human-in-the-Loop approval in HTTP proxy mode
require_approval_tools:
  - execute_sql
  - run_command
  - shell_exec
  - delete_file
  - send_email
  - transfer_funds

approval_timeout_seconds: 60.0

denied_paths:
  - .env
  - .ssh
  - id_rsa
  - id_ed25519
  - /etc/shadow
  - .aws/credentials
  - .kube/config
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-sentry",
        description="MCP-Sentry v2.0: Zero-Trust Security Gateway, Firewall & Audit Proxy for MCP",
    )
    parser.add_argument("--version", action="version", version=f"mcp-sentry {VERSION}")
    sub = parser.add_subparsers(dest="subcommand")

    # 1. wrap (stdio)
    p_wrap = sub.add_parser("wrap", help="Wrap a local stdio MCP server with bidirectional firewall")
    p_wrap.add_argument("--policy", type=str, default="", help="Path to sentry.yaml / sentry.json (hot-reloaded)")
    p_wrap.add_argument("--max-loop", type=int, default=3, help="Max identical calls per window (default: 3)")
    p_wrap.add_argument("--window", type=float, default=60.0, help="Loop sliding window in seconds (default: 60)")
    p_wrap.add_argument("--audit-dir", type=str, default="", help="Directory for cryptographic audit ledger")
    p_wrap.add_argument("command", nargs=argparse.REMAINDER, help="Target MCP server command after '--'")

    # 2. proxy (HTTP / Streamable-HTTP + Live Web UI)
    p_proxy = sub.add_parser("proxy", help="Run HTTP/Streamable-HTTP MCP gateway with Live Web UI & HITL gate")
    p_proxy.add_argument("--upstream", type=str, required=True, help="Upstream MCP HTTP endpoint URL")
    p_proxy.add_argument("--host", type=str, default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    p_proxy.add_argument("--port", type=int, default=8787, help="Bind port (default: 8787)")
    p_proxy.add_argument("--policy", type=str, default="", help="Path to sentry.yaml / sentry.json")
    p_proxy.add_argument("--audit-dir", type=str, default="", help="Directory for cryptographic audit ledger")

    # 3. bench
    sub.add_parser("bench", help="Run built-in 24-vector MCP red-team security benchmark")

    # 4. audit
    p_audit = sub.add_parser("audit", help="Verify cryptographic hash-chain integrity of audit ledger")
    p_audit.add_argument("--verify", action="store_true", default=True, help="Verify SHA-256 hash chain & HMAC signatures")
    p_audit.add_argument("--audit-dir", type=str, default="", help="Directory containing audit_ledger.jsonl")

    # 5. init
    p_init = sub.add_parser("init", help="Generate a default sentry.yaml Policy-as-Code file")
    p_init.add_argument("--output", type=str, default="sentry.yaml", help="Output path (default: sentry.yaml)")

    return parser


def main(argv=None):
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # Backwards compatibility with v0.1.0: `mcp-sentry [--max-loop N] -- <cmd>`
    known_subs = {"wrap", "proxy", "bench", "audit", "init", "-h", "--help", "--version"}
    if raw_args and raw_args[0] not in known_subs:
        raw_args = ["wrap"] + raw_args

    parser = _build_parser()
    args = parser.parse_args(raw_args)

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "bench":
        res = run_benchmark(verbose=True)
        return 0 if res["passed"] == res["total"] else 1

    if args.subcommand == "init":
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(DEFAULT_SENTRY_YAML)
        print(f"[MCP-Sentry] Generated Policy-as-Code template at: {os.path.abspath(args.output)}")
        return 0

    if args.subcommand == "audit":
        ledger = AuditLedger(log_dir=args.audit_dir or None)
        valid, count, msg = ledger.verify_chain()
        print(f"[MCP-Sentry Audit] {msg}")
        return 0 if valid else 2

    if args.subcommand == "wrap":
        target_cmd = list(args.command)
        if target_cmd and target_cmd[0] == "--":
            target_cmd = target_cmd[1:]
        if not target_cmd:
            sys.stderr.write("Error: No target MCP server command provided.\nUsage: mcp-sentry wrap -- <command> [args...]\n")
            return 1
        base_pol = SentryPolicy(max_identical_calls=args.max_loop, loop_window_seconds=args.window)
        pm = PolicyManager(policy_path=args.policy or None, policy=base_pol)
        ledger = AuditLedger(log_dir=args.audit_dir or None)
        return run_stdio_proxy(target_cmd=target_cmd, policy_manager=pm, ledger=ledger)

    if args.subcommand == "proxy":
        pm = PolicyManager(policy_path=args.policy or None)
        ledger = AuditLedger(log_dir=args.audit_dir or None)
        run_http_proxy(
            upstream_url=args.upstream,
            host=args.host,
            port=args.port,
            policy_manager=pm,
            ledger=ledger,
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
