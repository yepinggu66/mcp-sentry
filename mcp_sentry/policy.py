"""
Policy-as-Code engine with zero-dependency YAML/JSON parsing and automatic hot-reload.
"""

import json
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SentryPolicy:
    # Circuit breaker & cost controls
    max_identical_calls: int = 3
    loop_window_seconds: float = 60.0
    max_session_calls: int = 200
    max_calls_per_minute: int = 60

    # Threat engine toggles
    block_tool_poisoning: bool = True
    block_rug_pull: bool = True
    block_destructive_commands: bool = True
    block_secret_exfiltration: bool = True
    enable_taint_tracking: bool = True
    redact_response_secrets: bool = True
    enable_entropy_scan: bool = True
    entropy_threshold: float = 4.6

    # Human-in-the-loop approval gate (HTTP proxy mode)
    require_approval_tools: List[str] = field(
        default_factory=lambda: [
            "execute_sql",
            "run_command",
            "shell_exec",
            "delete_file",
            "send_email",
            "transfer_funds",
        ]
    )
    approval_timeout_seconds: float = 60.0
    approval_webhook_url: str = ""
    public_base_url: str = ""

    # Access controls
    allowed_tools: List[str] = field(default_factory=list)  # empty = allow all except denied
    denied_tools: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)  # optional directory sandbox
    denied_paths: List[str] = field(
        default_factory=lambda: [
            ".env",
            ".ssh",
            "id_rsa",
            "id_ed25519",
            "/etc/shadow",
            "/etc/passwd",
            ".aws/credentials",
            ".kube/config",
        ]
    )
    allowed_domains: List[str] = field(default_factory=list)  # if non-empty, outbound URLs must match
    outbound_tools: List[str] = field(
        default_factory=lambda: [
            "fetch",
            "http_request",
            "curl",
            "webhook",
            "send_email",
            "slack_post",
            "post_message",
            "upload",
            "web_request",
        ]
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SentryPolicy":
        p = cls()
        for k, v in data.items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_identical_calls": self.max_identical_calls,
            "loop_window_seconds": self.loop_window_seconds,
            "max_session_calls": self.max_session_calls,
            "max_calls_per_minute": self.max_calls_per_minute,
            "block_tool_poisoning": self.block_tool_poisoning,
            "block_rug_pull": self.block_rug_pull,
            "block_destructive_commands": self.block_destructive_commands,
            "block_secret_exfiltration": self.block_secret_exfiltration,
            "enable_taint_tracking": self.enable_taint_tracking,
            "redact_response_secrets": self.redact_response_secrets,
            "enable_entropy_scan": self.enable_entropy_scan,
            "entropy_threshold": self.entropy_threshold,
            "require_approval_tools": self.require_approval_tools,
            "approval_timeout_seconds": self.approval_timeout_seconds,
            "approval_webhook_url": self.approval_webhook_url,
            "public_base_url": self.public_base_url,
            "allowed_tools": self.allowed_tools,
            "denied_tools": self.denied_tools,
            "allowed_paths": self.allowed_paths,
            "denied_paths": self.denied_paths,
            "allowed_domains": self.allowed_domains,
            "outbound_tools": self.outbound_tools,
        }


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Minimal zero-dependency YAML subset parser for flat keys and string lists."""
    result: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.lstrip()
        if stripped.startswith("- ") and current_list_key is not None:
            val = stripped[2:].strip().strip('"').strip("'")
            result[current_list_key].append(val)
            continue
        if ":" in stripped:
            key, rest = stripped.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            if rest == "" or rest == "[]":
                result[key] = []
                current_list_key = key
            else:
                current_list_key = None
                if rest.startswith("[") and rest.endswith("]"):
                    inner = rest[1:-1].strip()
                    if not inner:
                        result[key] = []
                    else:
                        result[key] = [
                            item.strip().strip('"').strip("'")
                            for item in inner.split(",")
                            if item.strip()
                        ]
                elif rest.lower() in ("true", "yes"):
                    result[key] = True
                elif rest.lower() in ("false", "no"):
                    result[key] = False
                else:
                    cleaned = rest.strip('"').strip("'")
                    try:
                        if "." in cleaned:
                            result[key] = float(cleaned)
                        else:
                            result[key] = int(cleaned)
                    except ValueError:
                        result[key] = cleaned
    return result


def load_policy_file(path: str) -> SentryPolicy:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith(".json"):
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text) or {}
        except ImportError:
            data = _parse_simple_yaml(text)
    return SentryPolicy.from_dict(data)


class PolicyManager:
    """Thread-safe policy holder with automatic mtime-based hot-reload."""

    def __init__(self, policy_path: Optional[str] = None, policy: Optional[SentryPolicy] = None):
        self.policy_path = policy_path
        self._policy = policy or SentryPolicy()
        self._mtime: float = 0.0
        self._lock = threading.Lock()
        if policy_path and os.path.exists(policy_path):
            self.reload()

    def reload(self) -> bool:
        if not self.policy_path or not os.path.exists(self.policy_path):
            return False
        try:
            mtime = os.path.getmtime(self.policy_path)
            if mtime != self._mtime:
                new_policy = load_policy_file(self.policy_path)
                with self._lock:
                    self._policy = new_policy
                    self._mtime = mtime
                return True
        except Exception:
            pass
        return False

    @property
    def policy(self) -> SentryPolicy:
        if self.policy_path:
            self.reload()
        with self._lock:
            return self._policy
