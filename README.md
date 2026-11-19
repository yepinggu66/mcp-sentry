# 🛡️ MCP-Sentry

> A lightweight, zero-dependency circuit breaker and audit proxy for the Model Context Protocol (MCP).

MCP-Sentry wraps any stdio-based MCP server to prevent runaway tool loops, block destructive commands, and log all tool interactions.

---

## Why MCP-Sentry?

When using autonomous AI agents (Claude Desktop, Cursor, Windsurf, or custom LangChain/AutoGen loops) with MCP tools:
1. **Loop Storms**: If a tool returns an error, agents often retry cyclically with slight variations, burning API credits rapidly.
2. **Security & Data Safety**: Unrestricted MCP tools can access local directories, read private files (`.env`, keys), or run destructive commands (`rm -rf`, `DROP TABLE`).
3. **Audit Visibility**: Developers lack visibility into tool parameters, timestamps, and error responses.

MCP-Sentry acts as a transparent proxy between the AI client and target MCP servers.

---

## Key Features

- **Loop Circuit Breaker**: Tracks identical or cyclical calls in a sliding time window (default: 3 calls within 60s). Automatically trips the circuit and returns an error response before burning further API tokens.
- **Safety Interceptor**: Blocks destructive commands and access to sensitive files (`.env`, private keys).
- **Audit Logging**: Logs every tool call, latency, and status to `~/.mcp-sentry/audit.log`.
- **Zero Dependencies**: Single-file Python implementation with no third-party libraries required.

---

## Quick Setup

### 1. Installation

```bash
git clone https://github.com/yepinggu66/mcp-sentry.git
cd mcp-sentry
pip install .
```

Or run directly with Python:

```bash
python mcp_sentry.py -- <target_command> [args...]
```

### 2. Configure in Claude Desktop / Cursor

Prepend `mcp-sentry --` to your server command in `claude_desktop_config.json` or `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "protected-server": {
      "command": "mcp-sentry",
      "args": ["--", "python", "my_server.py"]
    }
  }
}
```

---

## Interactive Workbench

You can test the audit rules and circuit breaker simulator in our live workbench:
- **Online Console**: [https://pingguye.cn/stackverdict/agentwall](https://pingguye.cn/stackverdict/agentwall)

## Author

- **Yongping Ye** (`yepinggu66@gmail.com`)
- Repository: [https://github.com/yepinggu66/mcp-sentry](https://github.com/yepinggu66/mcp-sentry)
- License: MIT
