"""
MCP-Sentry v2.0.0 — Zero-Trust Security Gateway, Firewall & Cryptographic Audit Proxy
for the Model Context Protocol (MCP).

Author: Ye Yongping (yepinggu66@gmail.com)
Repository: https://github.com/yepinggu66/mcp-sentry
"""

VERSION = "2.0.0"

from .policy import SentryPolicy, PolicyManager
from .detectors import ThreatEngine, ThreatVerdict, SchemaLockStore
from .circuit_breaker import CircuitBreaker, BudgetState
from .ledger import AuditLedger

__all__ = [
    "VERSION",
    "SentryPolicy",
    "PolicyManager",
    "ThreatEngine",
    "ThreatVerdict",
    "SchemaLockStore",
    "CircuitBreaker",
    "BudgetState",
    "AuditLedger",
]
