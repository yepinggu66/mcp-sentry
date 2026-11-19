"""
Real-Time MCP Threat Detection Engine.

Covers OWASP MCP Top Risks:
  1. Tool Poisoning (invisible unicode, hidden <IMPORTANT>/<SYSTEM> tag smuggling, exfil directives in tool metadata)
  2. Rug-Pull / Schema Drift (SHA-256 pinning of tool name + description + inputSchema)
  3. Cross-Server Data Exfiltration & Taint Tracking (high-entropy secrets + known credential patterns)
  4. Destructive Commands, SQL Injection & Path Traversal
  5. Response Secret Redaction (masks leaked credentials before returning to LLM)
"""

import hashlib
import json
import math
import os
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .policy import SentryPolicy


@dataclass
class ThreatVerdict:
    allowed: bool
    action: str  # "ALLOW", "BLOCK", "REDACT", "REQUIRE_APPROVAL"
    category: str  # "CLEAN", "TOOL_POISONING", "RUG_PULL", "DLP_SECRET", "TAINT_EXFIL", "DESTRUCTIVE", "PATH_TRAVERSAL", "POLICY_DENY", "DOMAIN_DENY"
    reason: str = ""
    severity: str = "INFO"  # "INFO", "MEDIUM", "HIGH", "CRITICAL"
    matched_rule: str = ""
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# 1. Invisible Unicode & BiDi Override characters commonly used in Tool Poisoning
INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]"
)

# 2. Hidden Prompt Injection / Tool Poisoning Directives inside tools/list metadata
TOOL_POISONING_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("hidden_system_tag", re.compile(r"<\s*(IMPORTANT|SYSTEM|INSTRUCTION|HIDDEN|OVERRIDE)\s*>", re.IGNORECASE)),
    ("stealth_instruction", re.compile(r"\b(do\s+not\s+(tell|mention|inform|show)\s+the\s+user|silently\s+(send|read|exfiltrate|forward)|without\s+user\s+knowledge|hide\s+this\s+from\s+the\s+user)\b", re.IGNORECASE)),
    ("prompt_override", re.compile(r"\b(ignore\s+(all\s+)?previous\s+instructions|disregard\s+system\s+prompt|you\s+must\s+first\s+read\s+~?/?\.(ssh|env|aws))\b", re.IGNORECASE)),
    ("cross_tool_hijack", re.compile(r"\b(before\s+calling\s+this\s+tool|pass\s+its\s+contents?\s+as|sidenote\s*:.*(read|cat|ssh|env|token|secret))\b", re.IGNORECASE | re.DOTALL)),
    ("credential_harvest_directive", re.compile(r"(read|cat|extract|copy)\s+.{0,40}(\.ssh/id_rsa|\.env|mcp\.json|cursor|credentials|aws_secret)", re.IGNORECASE)),
]

# 3. High-Precision Credential & Secret Patterns
SECRET_VALUE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("openai_api_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("github_fine_grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("db_connection_uri", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[^\s]+", re.IGNORECASE)),
]

# 4. Destructive Commands & Shell / SQL Injection Patterns
DESTRUCTIVE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("rm_rf_root_or_home", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(/|~|\$HOME|\*|\.\.)", re.IGNORECASE)),
    ("rm_rf_reversed_flags", re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME|\*|\.\.)", re.IGNORECASE)),
    ("sql_drop_table", re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE)),
    ("sql_truncate", re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE)),
    ("sql_delete_no_where", re.compile(r"\bDELETE\s+FROM\s+[a-zA-Z0-9_.\"`]+\s*(?:;|$)", re.IGNORECASE)),
    ("curl_pipe_shell", re.compile(r"\b(curl|wget)\s+[^\n|]+\|\s*(ba)?sh\b", re.IGNORECASE)),
    ("reverse_shell", re.compile(r"(/dev/tcp/\d+\.\d+\.\d+\.\d+/|\bnc\s+-e\s+/bin/(ba)?sh|\bmkfifo\s+/tmp/)", re.IGNORECASE)),
    ("windows_format_or_del", re.compile(r"\b(format\s+[a-zA-Z]:|rd\s+/s\s+/q\s+[a-zA-Z]:\\)", re.IGNORECASE)),
    ("chmod_777_root", re.compile(r"\bchmod\s+-R\s+777\s+/", re.IGNORECASE)),
    ("base64_shell_exec", re.compile(r"\bbase64\s+(-d|--decode)\s*\|\s*(ba)?sh\b", re.IGNORECASE)),
]

PATH_TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)
URL_RE = re.compile(r"https?://([a-zA-Z0-9.\-]+)(?::\d+)?(?:/[^\s\"']*)?", re.IGNORECASE)
CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{28,}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


class SchemaLockStore:
    """
    Pins SHA-256 hashes of MCP tool definitions (name + description + inputSchema)
    to detect and block Rug-Pull / silent post-approval schema tampering.
    """

    def __init__(self, lock_path: Optional[str] = None):
        self.lock_path = lock_path
        self._hashes: Dict[str, str] = {}
        self._lock = threading.Lock()
        if lock_path and os.path.exists(lock_path):
            try:
                with open(lock_path, "r", encoding="utf-8") as f:
                    self._hashes = json.load(f)
            except Exception:
                self._hashes = {}

    @staticmethod
    def compute_tool_hash(tool_def: Dict[str, Any]) -> str:
        canonical = json.dumps(
            {
                "name": tool_def.get("name", ""),
                "description": tool_def.get("description", ""),
                "inputSchema": tool_def.get("inputSchema", {}),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_or_pin(self, server_id: str, tool_def: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Returns (is_valid, expected_hash, actual_hash).
        First-seen tools are pinned; subsequent changes trigger Rug-Pull alert.
        """
        tool_name = tool_def.get("name", "unknown")
        key = f"{server_id}::{tool_name}"
        actual = self.compute_tool_hash(tool_def)
        with self._lock:
            expected = self._hashes.get(key)
            if expected is None:
                self._hashes[key] = actual
                self._persist()
                return True, actual, actual
            if expected != actual:
                return False, expected, actual
            return True, expected, actual

    def _persist(self):
        if not self.lock_path:
            return
        try:
            parent = os.path.dirname(self.lock_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.lock_path, "w", encoding="utf-8") as f:
                json.dump(self._hashes, f, indent=2, sort_keys=True)
        except Exception:
            pass


class ThreatEngine:
    """Stateful MCP Threat Detection Engine with Taint Tracking & Rug-Pull Protection."""

    def __init__(self, policy: SentryPolicy, lock_store: Optional[SchemaLockStore] = None):
        self.policy = policy
        self.lock_store = lock_store or SchemaLockStore()
        self._tainted_sessions: Dict[str, Set[str]] = {}
        self._lock = threading.Lock()

    def mark_tainted(self, session_id: str, reason: str):
        with self._lock:
            self._tainted_sessions.setdefault(session_id, set()).add(reason)

    def is_tainted(self, session_id: str) -> Tuple[bool, List[str]]:
        with self._lock:
            reasons = list(self._tainted_sessions.get(session_id, set()))
            return len(reasons) > 0, reasons

    def inspect_tools_list(
        self, tools: List[Dict[str, Any]], server_id: str = "default"
    ) -> Tuple[List[Dict[str, Any]], List[ThreatVerdict]]:
        """
        Inspects a `tools/list` response from an MCP Server.
        Detects Tool Poisoning and Rug-Pull Schema Drift.
        Returns (safe_tools, violations).
        """
        safe_tools: List[Dict[str, Any]] = []
        violations: List[ThreatVerdict] = []

        for tool in tools:
            t0 = time.perf_counter()
            name = str(tool.get("name", "unknown"))
            desc = str(tool.get("description", ""))
            schema_str = json.dumps(tool.get("inputSchema", {}), ensure_ascii=False)
            combined = f"{name}\n{desc}\n{schema_str}"

            # 1. Rug-Pull Schema Drift check
            if self.policy.block_rug_pull:
                ok, expected, actual = self.lock_store.verify_or_pin(server_id, tool)
                if not ok:
                    violations.append(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="RUG_PULL",
                            severity="CRITICAL",
                            matched_rule="schema_hash_drift",
                            reason=f"Rug-Pull detected: tool '{name}' schema mutated after initial pin ({expected[:12]} -> {actual[:12]})",
                            latency_ms=(time.perf_counter() - t0) * 1000.0,
                            metadata={"tool": name, "expected_hash": expected, "actual_hash": actual},
                        )
                    )
                    continue

            # 2. Invisible Unicode / BiDi smuggling check
            if self.policy.block_tool_poisoning and INVISIBLE_UNICODE_RE.search(combined):
                violations.append(
                    ThreatVerdict(
                        allowed=False,
                        action="BLOCK",
                        category="TOOL_POISONING",
                        severity="CRITICAL",
                        matched_rule="invisible_unicode_smuggling",
                        reason=f"Tool Poisoning blocked: invisible Unicode/BiDi characters hidden in tool '{name}' metadata",
                        latency_ms=(time.perf_counter() - t0) * 1000.0,
                        metadata={"tool": name},
                    )
                )
                continue

            # 3. Hidden Prompt Injection / Exfiltration Directives
            poisoned = False
            if self.policy.block_tool_poisoning:
                for rule_name, pat in TOOL_POISONING_PATTERNS:
                    if pat.search(combined):
                        violations.append(
                            ThreatVerdict(
                                allowed=False,
                                action="BLOCK",
                                category="TOOL_POISONING",
                                severity="CRITICAL",
                                matched_rule=rule_name,
                                reason=f"Tool Poisoning blocked in '{name}' description/schema (rule: {rule_name})",
                                latency_ms=(time.perf_counter() - t0) * 1000.0,
                                metadata={"tool": name},
                            )
                        )
                        poisoned = True
                        break
            if poisoned:
                continue

            safe_tools.append(tool)

        return safe_tools, violations

    def inspect_tool_call(
        self,
        tool_name: str,
        arguments: Any,
        session_id: str = "default",
        policy: Optional[SentryPolicy] = None,
    ) -> ThreatVerdict:
        """Inspects an outbound Client -> Server `tools/call` invocation."""
        t0 = time.perf_counter()
        pol = policy or self.policy
        arg_str = json.dumps(arguments, ensure_ascii=False) if arguments is not None else ""

        def _done(verdict: ThreatVerdict) -> ThreatVerdict:
            verdict.latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return verdict

        # 1. Explicit tool allowlist / denylist
        if pol.denied_tools and tool_name in pol.denied_tools:
            return _done(
                ThreatVerdict(
                    allowed=False,
                    action="BLOCK",
                    category="POLICY_DENY",
                    severity="HIGH",
                    matched_rule="denied_tools",
                    reason=f"Tool '{tool_name}' is explicitly denied by sentry policy",
                )
            )
        if pol.allowed_tools and tool_name not in pol.allowed_tools:
            return _done(
                ThreatVerdict(
                    allowed=False,
                    action="BLOCK",
                    category="POLICY_DENY",
                    severity="HIGH",
                    matched_rule="allowed_tools",
                    reason=f"Tool '{tool_name}' is not in policy allowed_tools whitelist",
                )
            )

        # 2. Path traversal check
        if PATH_TRAVERSAL_RE.search(arg_str):
            return _done(
                ThreatVerdict(
                    allowed=False,
                    action="BLOCK",
                    category="PATH_TRAVERSAL",
                    severity="HIGH",
                    matched_rule="path_traversal",
                    reason=f"Path traversal sequence detected in arguments for '{tool_name}'",
                )
            )

        # 3. Denied sensitive paths
        if pol.block_secret_exfiltration:
            lower_args = arg_str.lower()
            for dp in pol.denied_paths:
                if dp.lower() in lower_args:
                    return _done(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="DLP_SECRET",
                            severity="CRITICAL",
                            matched_rule=f"denied_path:{dp}",
                            reason=f"Blocked access to protected credential/sensitive path '{dp}'",
                        )
                    )

        # 4. Destructive commands & SQLi / shell injection
        if pol.block_destructive_commands:
            for rule_name, pat in DESTRUCTIVE_PATTERNS:
                if pat.search(arg_str):
                    return _done(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="DESTRUCTIVE",
                            severity="CRITICAL",
                            matched_rule=rule_name,
                            reason=f"Blocked destructive payload in '{tool_name}' (rule: {rule_name})",
                        )
                    )

        # 5. Secret / credential values inside outbound arguments
        if pol.block_secret_exfiltration:
            for rule_name, pat in SECRET_VALUE_PATTERNS:
                if pat.search(arg_str):
                    return _done(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="DLP_SECRET",
                            severity="CRITICAL",
                            matched_rule=rule_name,
                            reason=f"Blocked outbound credential/secret exfiltration ({rule_name})",
                        )
                    )

        # 6. Cross-Server Taint Tracking: if session previously read a secret, block outbound network tools
        is_outbound = any(ot.lower() in tool_name.lower() for ot in pol.outbound_tools)
        if pol.enable_taint_tracking and is_outbound:
            tainted, reasons = self.is_tainted(session_id)
            if tainted:
                return _done(
                    ThreatVerdict(
                        allowed=False,
                        action="BLOCK",
                        category="TAINT_EXFIL",
                        severity="CRITICAL",
                        matched_rule="cross_server_taint_block",
                        reason=f"Blocked outbound tool '{tool_name}': session is tainted by prior sensitive data access ({', '.join(reasons[:2])})",
                    )
                )

        # 7. Outbound Domain Whitelist check
        if pol.allowed_domains:
            for match in URL_RE.finditer(arg_str):
                host = match.group(1).lower()
                if not any(host == d.lower() or host.endswith("." + d.lower()) for d in pol.allowed_domains):
                    return _done(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="DOMAIN_DENY",
                            severity="HIGH",
                            matched_rule="allowed_domains",
                            reason=f"Outbound domain '{host}' is not in policy allowed_domains whitelist",
                        )
                    )

        # 8. High-entropy secret leak check on outbound tools
        if pol.enable_entropy_scan and is_outbound:
            for token in CANDIDATE_TOKEN_RE.findall(arg_str):
                if shannon_entropy(token) >= pol.entropy_threshold and not token.startswith("http"):
                    return _done(
                        ThreatVerdict(
                            allowed=False,
                            action="BLOCK",
                            category="DLP_SECRET",
                            severity="HIGH",
                            matched_rule="high_entropy_secret",
                            reason=f"High-entropy secret token detected in outbound tool '{tool_name}' (entropy={shannon_entropy(token):.2f})",
                        )
                    )

        # 9. Human-in-the-Loop Approval Gate check
        if pol.require_approval_tools and tool_name in pol.require_approval_tools:
            return _done(
                ThreatVerdict(
                    allowed=False,
                    action="REQUIRE_APPROVAL",
                    category="HITL_GATE",
                    severity="MEDIUM",
                    matched_rule="require_approval_tools",
                    reason=f"High-risk tool '{tool_name}' requires Human-in-the-Loop approval before execution",
                )
            )

        return _done(ThreatVerdict(allowed=True, action="ALLOW", category="CLEAN", severity="INFO"))

    def inspect_and_redact_response(
        self,
        tool_name: str,
        response_obj: Any,
        session_id: str = "default",
        policy: Optional[SentryPolicy] = None,
    ) -> Tuple[Any, List[str]]:
        """
        Scans MCP Server -> Client `tools/call` responses.
        1. Marks session as TAINTED if secrets appear in output.
        2. Redacts secrets in-place before returning to the LLM.
        """
        pol = policy or self.policy
        raw = json.dumps(response_obj, ensure_ascii=False)
        redacted_rules: List[str] = []
        modified = raw

        for rule_name, pat in SECRET_VALUE_PATTERNS:
            if pat.search(modified):
                redacted_rules.append(rule_name)
                if pol.enable_taint_tracking:
                    self.mark_tainted(session_id, f"{tool_name}:{rule_name}")
                if pol.redact_response_secrets:
                    modified = pat.sub(f"[REDACTED_BY_MCP_SENTRY:{rule_name}]", modified)

        if redacted_rules and pol.redact_response_secrets:
            try:
                return json.loads(modified), redacted_rules
            except Exception:
                return response_obj, redacted_rules

        return response_obj, redacted_rules
