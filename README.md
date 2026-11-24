# 🛡️ MCP-Sentry v3.0 — Self-Evolving Security Gateway, Time-Machine Rollback & USD Budget Crusher for MCP

> **Zero external dependencies. Sub-millisecond latency (0.031 ms avg). Bidirectional JSON-RPC 2.0 firewall, 1-click Time-Machine file rollback, real-time USD Token Diet compressor, and Self-Evolving Behavioral Immunity for Claude Code, Cursor, Windsurf & Enterprise MCP fleets.**

[![Version](https://img.shields.io/badge/version-3.0.0-emerald.svg)](https://github.com/yepinggu66/mcp-sentry/releases)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(Pure%20Python)-blue.svg)](#quick-start)
[![Benchmark](https://img.shields.io/badge/red--team%20benchmark-24%2F24%20blocked-brightgreen.svg)](#24-vector-red-team-benchmark)
[![License](https://img.shields.io/badge/License-Open--Core%20%2F%20Commercial-amber.svg)](#community-vs-pro-49-vs-full-ip-buyout-30000)

> **📢 Important Notice (v2.0 vs. v3.0 Evolution):** `MCP-Sentry v2.0.0` was almost completely free. With the major evolutionary leap in **`MCP-Sentry v3.0.0`** (1-Click Time-Machine File Rollback, Smart USD Token Diet, Self-Evolving Behavioral Immunity & Signed SOC2 Compliance Dossiers), **all evolutionary production features are strictly commercial and require a paid Pro License ($49) or the $30,000 Full IP & Master Keygen Buyout.**

---

## 🚀 What's New in v3.0 (Why Developers & Enterprises Upgrade)

1. **⏪ ShadowVault Time-Machine (`mcp-sentry rollback`)**
   - Automatically captures 0.1ms content-addressed delta snapshots before any mutating MCP tool (`write_file`, `edit_file`, `delete_file`, `patch`) modifies your codebase.
   - Did an AI agent hallucinate, corrupt 6 files, or break an uncommitted workspace? Run `mcp-sentry rollback` (or click **⏪ 1-Click Time-Machine Rollback** in the Live Web UI) to restore every file to its exact pre-agent byte state in 1 second!
2. **💰 Real-Time USD Budget Crusher & Smart Payload Diet (`TokenDietEngine`)**
   - Calculates real-time token & USD burn across both requests and bloated MCP responses (`max_session_usd: 5.00`).
   - **Smart Payload Diet**: Automatically trims massive 100KB+ JSON/log dumps from MCP tools down to high-signal head+tail context before they enter your LLM window — **saving 50%–80% on daily Claude / OpenAI API bills**.
3. **🧬 Self-Evolving Behavioral Immunity (`AdaptiveImmunityEngine`)**
   - Every time an attack is blocked or an operator clicks **DENY** on the Human-in-the-Loop dashboard, MCP-Sentry extracts the AST/payload skeleton and synthesizes a new **Immunity Gene (`GENE-XXXXXXXX`)**, automatically immunizing your gateway against mutated follow-up attempts.
4. **🪤 Active Canary Honeypot Trap (`CanaryHoneypot`)**
   - Mints watermarked decoy credentials (`sk-proj-SENTRYCANARY...`, `AKIASENTRY...`) to bait untrusted MCP servers. Any outbound tool attempting to exfiltrate a canary token is caught with **0% false positives** and permanently quarantined.
5. **📄 Cryptographic SOC2 / EU AI Act Compliance Dossier Exporter (`mcp-sentry audit --export-soc2 report.html`)**
   - Exports a self-contained, SHA-256 hash-chained & HMAC-signed HTML compliance report for security audits.

---

## 💎 Community vs. Pro ($49) vs. Full IP Buyout ($30,000)

| Capability | Community (Free Eval) | ⚡ Developer Pro ($49 One-Time) | 🏛️ Enterprise / Full IP Buyout ($30,000) |
| :--- | :---: | :---: | :---: |
| 24-Vector OWASP MCP Threat Firewall (`stdio` + `HTTP`) | ✅ Unlimited | ✅ Unlimited | ✅ Unlimited + White-Label IP |
| **⏪ ShadowVault Time-Machine File Rollback** | 1 file / session (Eval) | **✅ Unlimited Files & Sessions** | **✅ Unlimited + Fleet Sync** |
| **💰 Smart Payload Diet (Saves 50%–80% API USD)** | 3 compressions / session | **✅ Unlimited Auto-Diet & USD Cap** | **✅ Unlimited + Cost Telemetry** |
| **🧬 Self-Evolving Behavioral Immunity Genome** | 3 in-memory genes / session | **✅ Persistent Genome + 65-Rule Enterprise Pack** | **✅ Master Genome Vault + Signer** |
| **📄 SOC2 / EU AI Act HTML Audit Certificate** | Watermarked (`[EVAL]`) | **✅ Official Signed Commercial Seal** | **✅ Custom Branded Compliance Seal** |
| **Commercial SaaS Redistribution & Master Keygen** | ❌ Prohibited | Single-Org Production Use | **✅ 100% Exclusive IP & Master Keygen** |

- 👉 **Unlock Developer Pro ($49 One-Time — Pays for itself in 1 week of saved Claude API tokens)**: [Instant PayPal Checkout](https://www.paypal.com/ncp/payment/7G6M6X7889A2Q)
- 👉 **Acquire Full Turnkey IP & Master Keygen Vault ($30,000)**: [AgentWall M&A Sandbox & Console](https://pingguye.cn/stackverdict/agentwall) or email **yepinggu6@gmail.com**

---

## Quick Start

### 1. Install
```bash
git clone https://github.com/yepinggu66/mcp-sentry.git
cd mcp-sentry
pip install -e .
```

### 2. Check Evolutionary Status & Run 24-Vector Benchmark
```bash
mcp-sentry status
mcp-sentry bench
```

### 3. Wrap Any MCP Server in Cursor / Claude Desktop (`mcp.json`)
```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "mcp-sentry",
      "args": ["wrap", "--policy", "sentry.yaml", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}
```

### 4. Instant Time-Machine Rollback When an AI Agent Breaks Your Code
```bash
mcp-sentry rollback
```

### 5. Run HTTP Reverse Proxy + Live Firewall, Time-Machine & HITL Console
```bash
mcp-sentry init
mcp-sentry proxy --upstream http://127.0.0.1:9000/mcp --port 8787 --policy sentry.yaml
# Open http://127.0.0.1:8787/sentry/ui
```

### 6. Activate Your Pro / Enterprise License Key & Export Signed SOC2 Report
```bash
mcp-sentry activate SENTRY-V3-PRO-PERPETUAL-YOURNAME-XXXXXXXXXXXXXXXX
mcp-sentry audit --verify --export-soc2 soc2_compliance_certificate.html
```
