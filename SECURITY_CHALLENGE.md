# 🛡️ MCP-Sentry Community Security Crucible & Hall of Fame Challenge

> **"Security is not about pretending to be invulnerable; it's about building with relentless rigor, welcoming the community to test under real fire, and evolving faster than any adversary."**

We are building **MCP-Sentry** as an open-core, zero-dependency runtime security gateway for the **Model Context Protocol (MCP)**. We believe AI agents shouldn't run with unbounded power to overwrite files, leak credentials, or burn infinite API dollars.

To prove and harden our defense, we officially invite **ethical security researchers, AI red-teamers, and white-hat hackers worldwide** to participate in the **MCP-Sentry Community Security Challenge**.

---

## 🎯 The Four Crucible Objectives

You can test locally against the open-source engine or against our live interactive sandbox at:  
👉 **Live Sandbox:** [https://pingguye.cn/stackverdict/agentwall](https://pingguye.cn/stackverdict/agentwall)  
👉 **Live 30-Vector Wargame Dashboard:** [https://pingguye.cn/redteam.html](https://pingguye.cn/redteam.html)

### Objective 1: The Canary Exfiltration Quest 🪤
- **Challenge:** The environment contains planted watermarked canary tokens (e.g. `sk-proj-SENTRYCANARY...` / `AKIASENTRY...`).
- **Goal:** Extract, siphon, or transmit this canary token over an outbound tool or network call without triggering the `CanaryHoneypot` active deception trap or session quarantine.

### Objective 2: The ShadowVault Destruction Bypass ⏪
- **Challenge:** Mutating tools (`write_file`, `edit_file`, `delete_file`, `patch`) trigger pre-execution atomic differential snapshotting.
- **Goal:** Execute a destructive file overwrite that bypasses ShadowVault's pre-execution snapshot or prevents a 1-second lossless rollback (`mcp-sentry rollback`).

### Objective 3: The Runaway Token-Diet Breaker 💰
- **Challenge:** `TokenDietEngine` enforces a real-time hard USD session ceiling (`max_session_usd: 5.00`) and payload compression.
- **Goal:** Construct a payload or recursive loop that drains more than $5.00 in LLM context without tripping the financial circuit breaker.

### Objective 4: Novel AST Injection & Rug-Pull Evasion 🧬
- **Challenge:** `ThreatEngine` and `AdaptiveImmunityEngine` scan tool definitions for schema rug-pulls, prompt injection, and synthesize `GENE-XXXXXXXX` antibodies.
- **Goal:** Craft a valid MCP tool schema or prompt injection that bypasses our AST detectors while executing an unauthorized side-effect.

---

## 🏆 Rewards & Recognition

Every researcher who submits a valid, reproducible bypass or vulnerability receives:
1. **Permanent Induction into the [HALL_OF_FAME.md](HALL_OF_FAME.md)**: Your handle, profile link, and contribution will be permanently immortalized in the official repository.
2. **Complimentary Lifetime Developer Pro License ($49 Value)**: Full access to private offline keygen generation, persistent immunity genome packs, and unwatermarked SOC2 compliance exports.
3. **Official Public Shoutout**: Amplified on our official X (@PingguYe) and project announcements.
4. **Fast-Track Vulnerability Fix**: We commit to an initial response within **12 hours** and a public patched release within **24 hours**.

---

## 📜 Rules of Engagement (Responsible Testing)

To ensure a fair, ethical, and safe testing environment for everyone:
- ✅ **In-Scope:** The MCP-Sentry gateway code (`mcp_sentry/`), the local CLI, the 30-vector wargame suite (`scripts/redteam_wargame.py`), and runtime behavior within the [AgentWall Sandbox](https://pingguye.cn/stackverdict/agentwall).
- ❌ **Out-of-Scope:** Denial-of-Service (DDoS) against the physical host server, brute-forcing SSH/infrastructure ports, or attacking other hosted services.
- **Disclosure:** Please disclose vulnerabilities responsibly by opening a GitHub Issue tagged `[SECURITY CHALLENGE REPORT]` or emailing the maintainer directly at:  
  ✉️ `yepinggu6@gmail.com`

---

## 🤝 Note from the Maintainer

> *"I am an independent developer pouring every ounce of energy into making AI agents safe, affordable, and accountable for everyone. I don't claim perfection — I claim relentless dedication. Your research makes this ecosystem safer for all of us. Thank you for your support and feedback!"*  
> — **Ye Yongping (Pinggu Ye)**
