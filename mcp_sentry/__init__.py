"""
MCP-Sentry v3.0.0 — Self-Evolving Zero-Trust Security Gateway, Time-Machine Rollback,
Token/USD Budget Crusher & Cryptographic Audit Proxy for the Model Context Protocol (MCP).

Author: Ye Yongping (yepinggu66@gmail.com)
Repository: https://github.com/yepinggu66/mcp-sentry
"""

VERSION = "3.0.0"
__version__ = VERSION

from .policy import SentryPolicy, PolicyManager
from .detectors import ThreatEngine, ThreatVerdict, SchemaLockStore
from .circuit_breaker import CircuitBreaker, BudgetState
from .ledger import AuditLedger
from .license import LicenseStatus, verify_license_key
from .evolution import (
    ShadowVault,
    TokenDietEngine,
    AdaptiveImmunityEngine,
    CanaryHoneypot,
)

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
    "LicenseStatus",
    "verify_license_key",
    "ShadowVault",
    "TokenDietEngine",
    "AdaptiveImmunityEngine",
    "CanaryHoneypot",
]
