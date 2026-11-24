"""
MCP-Sentry v3.0.0 CLI entrypoint.
Supports:
  - `mcp-sentry wrap [options] -- <target_mcp_command>` (also backwards-compatible `mcp-sentry -- <cmd>`)
  - `mcp-sentry proxy --upstream <url> --port 8787`
  - `mcp-sentry rollback [--session <id>]` (Time-Machine 1-click file rollback)
  - `mcp-sentry activate <LICENSE_KEY>` (Activate $49 Pro or $24,800 Enterprise license)
  - `mcp-sentry status` (Show License tier, Evolved Immunity Genes, ShadowVault sessions)
  - `mcp-sentry bench`
  - `mcp-sentry audit --verify [--export-soc2 report.html]`
  - `mcp-sentry init`
"""

import argparse
import os
import sys

from . import VERSION
from .benchmark import run_benchmark
from .evolution import AdaptiveImmunityEngine, ShadowVault
from .ledger import AuditLedger
from .license import BUYOUT_CONSOLE_URL, PAYPAL_PRO_URL, verify_license_key
from .policy import PolicyManager, SentryPolicy
from .proxy_http import run_http_proxy
from .proxy_stdio import run_stdio_proxy


DEFAULT_SENTRY_YAML = """# MCP-Sentry v3.0 Policy-as-Code Configuration (Hot-Reloaded Automatically)
max_identical_calls: 3
loop_window_seconds: 60.0
max_session_calls: 200
max_calls_per_minute: 60
max_session_usd: 5.0
max_response_chars: 6000
enable_payload_diet: true

# v3.0 Evolutionary Defense Engines
enable_shadow_vault: true
enable_adaptive_immunity: true
enable_canary_honeypot: true
# license_key: "SENTRY-V3-PRO-PERPETUAL-..."

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
        description="MCP-Sentry v3.0: Self-Evolving Security Gateway, Time-Machine Rollback & USD Budget Crusher for MCP",
    )
    parser.add_argument("--version", action="version", version=f"mcp-sentry {VERSION}")
    sub = parser.add_subparsers(dest="subcommand")

    # 1. wrap (stdio)
    p_wrap = sub.add_parser("wrap", help="Wrap a local stdio MCP server with bidirectional firewall & time-machine")
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
    p_proxy.add_argument("--webhook-url", type=str, default="", help="Slack/Discord/generic webhook URL for remote HITL approval alerts")
    p_proxy.add_argument("--public-url", type=str, default="", help="Public base URL used to build direct deep-links to held requests")

    # 3. rollback (Time-Machine)
    p_rb = sub.add_parser("rollback", help="⏪ Instant Time-Machine rollback of files modified by an MCP session")
    p_rb.add_argument("--session", type=str, default="", help="Session ID to restore (defaults to latest session)")
    p_rb.add_argument("--audit-dir", type=str, default="", help="Base audit directory containing shadow_vault")

    # 4. activate (Commercial License)
    p_act = sub.add_parser("activate", help="⚡ Activate a Pro ($49) or Enterprise ($30,000) License Key")
    p_act.add_argument("key", type=str, help="License key string (SENTRY-V3-PRO-...)")

    # 5. status
    p_stat = sub.add_parser("status", help="Show License status, Evolved Immunity Genes & ShadowVault snapshots")
    p_stat.add_argument("--audit-dir", type=str, default="", help="Base audit directory")

    # 6. bench
    sub.add_parser("bench", help="Run built-in MCP red-team security benchmark")

    # 7. audit
    p_audit = sub.add_parser("audit", help="Verify cryptographic hash-chain integrity & export SOC2 compliance certificate")
    p_audit.add_argument("--verify", action="store_true", default=True, help="Verify SHA-256 hash chain & HMAC signatures")
    p_audit.add_argument("--export-soc2", type=str, default="", help="Export HTML SOC2 / EU AI Act Compliance Dossier to path")
    p_audit.add_argument("--audit-dir", type=str, default="", help="Directory containing audit_ledger.jsonl")

    # 8. init
    p_init = sub.add_parser("init", help="Generate a default sentry.yaml Policy-as-Code file")
    p_init.add_argument("--output", type=str, default="sentry.yaml", help="Output path (default: sentry.yaml)")

    return parser


def main(argv=None):
    raw_args = list(sys.argv[1:] if argv is None else argv)

    known_subs = {"wrap", "proxy", "rollback", "activate", "status", "bench", "audit", "init", "-h", "--help", "--version"}
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
        print(f"[MCP-Sentry v{VERSION}] Generated Policy-as-Code template at: {os.path.abspath(args.output)}")
        return 0

    if args.subcommand == "activate":
        lic = verify_license_key(args.key)
        if not lic.is_paid:
            sys.stderr.write(f"[MCP-Sentry LICENSE ERROR] {lic.reason}\n")
            sys.stderr.write(f"Get an official Pro License ($49): {PAYPAL_PRO_URL}\n")
            return 1
        key_dir = os.path.join(os.path.expanduser("~"), ".mcp-sentry")
        os.makedirs(key_dir, exist_ok=True)
        key_path = os.path.join(key_dir, "license.key")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(args.key.strip() + "\n")
        print(f"[MCP-Sentry v{VERSION}] ✅ Successfully activated {lic.tier} License for '{lic.licensee}'!")
        print(f"[MCP-Sentry] Saved to: {key_path}")
        return 0

    if args.subcommand == "rollback":
        base_dir = args.audit_dir or os.path.join(os.path.expanduser("~"), ".mcp-sentry")
        vault = ShadowVault(vault_dir=os.path.join(base_dir, "shadow_vault"))
        res = vault.rollback_session(session_id=args.session or None)
        print(f"[MCP-Sentry ShadowVault] {res['message']}")
        return 0 if res.get("ok") else 1

    if args.subcommand == "status":
        base_dir = args.audit_dir or os.path.join(os.path.expanduser("~"), ".mcp-sentry")
        lic = verify_license_key()
        vault = ShadowVault(vault_dir=os.path.join(base_dir, "shadow_vault"), license_status=lic)
        imm = AdaptiveImmunityEngine(genome_path=os.path.join(base_dir, "immunity_genome.json"), license_status=lic)
        print("=" * 74)
        print(f"  MCP-SENTRY v{VERSION} — COMMERCIAL & EVOLUTIONARY STATUS")
        print("=" * 74)
        print(f"  License Tier       : {lic.tier} ({lic.reason})")
        print(f"  ShadowVault        : {len(vault.list_sessions())} protected session(s)")
        print(f"  Immunity Genome    : {len(imm.list_genes())} evolved gene(s)")
        if not lic.is_paid:
            print("-" * 74)
            print(f"  ⚡ Upgrade to Pro ($49) — Unlock Unlimited Rollbacks, Smart Token Diet & SOC2 Seal:")
            print(f"     {PAYPAL_PRO_URL}")
            print(f"  🏛️ Full IP & Turnkey Buyout ($30,000): {BUYOUT_CONSOLE_URL}")
        print("=" * 74)
        return 0

    if args.subcommand == "audit":
        ledger = AuditLedger(log_dir=args.audit_dir or None)
        valid, count, msg = ledger.verify_chain()
        print(f"[MCP-Sentry Audit] {msg}")
        if args.export_soc2:
            html_report = ledger.export_soc2_html()
            with open(args.export_soc2, "w", encoding="utf-8") as f:
                f.write(html_report)
            lic = verify_license_key()
            wm_note = "SIGNED COMMERCIAL SEAL" if lic.is_paid else "UNLICENSED EVALUATION WATERMARK"
            print(f"[MCP-Sentry SOC2 Exporter] Wrote compliance dossier to {os.path.abspath(args.export_soc2)} ({wm_note})")
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
            webhook_url=args.webhook_url,
            public_base_url=args.public_url,
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
