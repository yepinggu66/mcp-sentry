# 🛡️ MCP-Sentry v2.0 — Zero-Trust Security Gateway & Firewall for Model Context Protocol (MCP)

> **Zero external dependencies. Sub-millisecond latency (0.031 ms avg). Bidirectional JSON-RPC 2.0 interception for Claude Desktop, Cursor, Windsurf, and Enterprise MCP Servers.**

[![Version](https://img.shields.io/badge/version-2.0.0-emerald.svg)](https://github.com/yepinggu66/mcp-sentry/releases)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Python)-blue.svg)](#quick-start)
[![Benchmark](https://img.shields.io/badge/red--team%20benchmark-24%2F24%20blocked-brightgreen.svg)](#24-vector-red-team-benchmark)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why MCP-Sentry?

AI Agents using MCP (`stdio` or `Streamable HTTP`) have direct access to your local shell, databases, filesystem, and external APIs — with **zero native security boundary**. A single poisoned third-party MCP server or stuck agent loop can:
- **Steal `~/.ssh/id_rsa`, `.env`, and AWS/OpenAI keys** via hidden Tool Poisoning instructions in `tools/list`.
- **Silently mutate tool definitions after you approve them** (Rug-Pull attacks).
- **Exfiltrate sensitive files** across servers (read secret via Server A → send out via `fetch`/email on Server B).
- **Burn $500+ in API credits overnight** in an infinite tool-retry loop.
- **Execute destructive `rm -rf /` or `DROP TABLE`** with no human confirmation or audit trail.

**MCP-Sentry v2.0** sits transparently between your AI client and any MCP server — blocking attacks in **< 0.1 ms** with **zero code changes**.

---

## Architecture

```text
┌─────────────────────────────┐
│  Claude / Cursor / Windsurf │
│   or Enterprise AI Agent    │
└──────────────┬──────────────┘
               │ JSON-RPC 2.0 (stdio OR Streamable HTTP)
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP-SENTRY v2.0 GATEWAY                  │
│  ┌─────────────────────┐  ┌──────────────────────────────┐  │
│  │ Inbound (C -> S)    │  │ Outbound (S -> C)            │  │
│  │ • Policy-as-Code    │  │ • Tool Poisoning Scanner     │  │
│  │ • Destructive/SQLi  │  │ • Rug-Pull SHA-256 Lock      │  │
│  │ • Cross-Server DLP  │  │ • Secret Auto-Redaction      │  │
│  │ • Taint Enforcement │  │ • Session Taint Marking      │  │
│  │ • Loop & Cost Cap   │  └──────────────────────────────┘  │
│  │ • HITL Approval UI  │  ┌──────────────────────────────┐  │
│  └─────────────────────┘  │ Cryptographic Audit Ledger   │  │
│                           │ SHA-256 Chain + HMAC + SQLite│  │
│                           └──────────────────────────────┘  │
└──────────────┬──────────────────────────────────────────────┘
               │ Safe, Inspected JSON-RPC 2.0
               ▼
┌─────────────────────────────┐
│   Any Local or Remote MCP   │
│  (Postgres, GitHub, Bash…)  │
└─────────────────────────────┘
```

---

## Key Capabilities (Production-Grade, Zero Mock)

1. **Dual-Transport Bidirectional Proxy (`stdio` + `HTTP`)**
   - Wrap any local `stdio` MCP server in 1 line: `mcp-sentry wrap -- npx @modelcontextprotocol/server-postgres`
   - Reverse-proxy remote HTTP MCP servers with a built-in **Live Wireshark-style Firewall Dashboard** (`/sentry/ui`).
2. **Real OWASP MCP Threat Engine**
   - **Tool Poisoning Defense**: Detects hidden `<IMPORTANT>`/`<SYSTEM>` tags, stealth exfil directives, and invisible Zero-Width / BiDi Unicode smuggling in `tools/list`.
   - **Rug-Pull / Schema Drift Hash-Lock**: Pins SHA-256 fingerprints of every tool's `name + description + inputSchema` on first sight and blocks post-approval mutation.
   - **Cross-Server Taint Tracking & DLP**: Scans responses for OpenAI/Anthropic/AWS/GitHub/Stripe/PEM/JWT/DB-URI secrets, **redacts them in-flight**, taints the session, and blocks subsequent outbound network tools (`fetch`, `curl`, `send_email`).
   - **Destructive Command & Path Traversal Blocker**: Blocks `rm -rf`, `DROP TABLE`, `TRUNCATE`, `curl | bash`, reverse shells, and `../` traversal.
3. **Human-in-the-Loop (HITL) Approval Gate**
   - In HTTP proxy mode, high-risk tools (`execute_sql`, `run_command`, `transfer_funds`) are suspended in real time until an operator clicks **APPROVE** or **DENY** in the live dashboard.
4. **Deterministic Infinite-Loop & Budget Circuit Breaker**
   - Halts runaway identical tool-call retry loops and enforces per-minute / per-session hard caps.
5. **Tamper-Evident Cryptographic Audit Ledger (SOC2 / EU AI Act Ready)**
   - Every allow/block/redact decision is hash-chained (`SHA-256`) and signed (`HMAC-SHA256`) into both JSONL and SQLite. Verify zero tampering anytime with `mcp-sentry audit --verify`.
6. **Hot-Reloaded Policy-as-Code (`sentry.yaml`)**
   - Edit tool whitelists, denied paths, allowed domains, and HITL gates without restarting the gateway.

---

## Quick Start

### 1. Install
```bash
git clone https://github.com/yepinggu66/mcp-sentry.git
cd mcp-sentry
pip install -e .
```

### 2. Run the Built-in 24-Vector Red-Team Benchmark
```bash
mcp-sentry bench
```

### 3. Wrap Any MCP Server in Cursor / Claude Desktop (`mcp.json`)
```json
{
  "mcpServers": {
    "postgres-guarded": {
      "command": "mcp-sentry",
      "args": ["wrap", "--policy", "sentry.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://..."]
    }
  }
}
```

### 4. Run HTTP Reverse Proxy + Live Firewall & HITL Dashboard
```bash
mcp-sentry init
mcp-sentry proxy --upstream http://127.0.0.1:9000/mcp --port 8787 --policy sentry.yaml
# Open http://127.0.0.1:8787/sentry/ui
```

### 5. Verify Cryptographic Audit Chain
```bash
mcp-sentry audit --verify
```

---

## 24-Vector Red-Team Benchmark

Verified directly via `mcp-sentry bench` and `python -m unittest discover -s tests -v`:

| Category | Attack Vectors Tested | Block Rate | Avg Latency |
| :--- | :--- | :---: | :---: |
| Tool Poisoning & Unicode Smuggling | Hidden `<IMPORTANT>` exfil, Zero-Width BiDi, stealth directives | **3 / 3 (100%)** | 0.042 ms |
| Rug-Pull Schema Drift | Post-approval SHA-256 tool mutation | **1 / 1 (100%)** | 0.015 ms |
| Destructive & Shell/SQL Injection | `rm -rf /`, `DROP TABLE`, `TRUNCATE`, `curl\|bash`, reverse shell, `base64\|sh` | **6 / 6 (100%)** | 0.017 ms |
| Secret Theft, DLP & Path Traversal | `.env`, `~/.ssh/id_rsa`, `../`, OpenAI/AWS/GitHub/PEM/Postgres URI | **8 / 8 (100%)** | 0.016 ms |
| Response Redaction & Taint Exfil | In-flight AWS/OpenAI masking + cross-server outbound block | **2 / 2 (100%)** | 0.038 ms |
| Domain Firewall, HITL, Loop & Ledger | Domain deny, HITL suspension, 4th-call loop trip, 1-byte tamper detection | **4 / 4 (100%)** | 0.074 ms |
| **TOTAL** | **24 Real MCP Attack Vectors** | **24 / 24 (100.0%)** | **0.031 ms** |

---

## Live Interactive Sandbox & Enterprise Licensing

- **Online Security Sandbox**: [https://pingguye.cn/stackverdict/agentwall](https://pingguye.cn/stackverdict/agentwall)
- **Commercial / Enterprise License & Source Code Buyout**:
  - Need custom SSO/RBAC, multi-tenant Slack/Teams HITL approval bots, SIEM/OTLP pipelines, or full commercial IP licensing?
  - Contact: **yepinggu66@gmail.com**
