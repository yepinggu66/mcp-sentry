"""
MCP-Sentry v3.0 Commercial License & Entitlement Engine.
Zero-dependency offline cryptographic license verification + evaluation quota enforcement.

Tiers:
  - COMMUNITY (Unlicensed default):
      * Full 28-vector core OWASP threat detection (keeps developers safe & drives viral adoption)
      * ShadowVault Time-Machine: 1 protected file snapshot per session (eval preview)
      * Token Vampire Killer (Smart Payload Diet): 3 auto-compressions per session + live USD meter
      * Self-Evolving Immunity: in-memory session evolution (up to 3 auto-synthesized rules)
      * SOC2 / EU AI Act HTML Compliance Certificate: watermarked [UNLICENSED EVALUATION]
  - PRO ($49 one-time Developer Pro License: SENTRY-V3-PRO-...):
      * Unlimited ShadowVault Time-Machine snapshots & 1-click session rollbacks
      * Unlimited Smart Payload Diet auto-compression & hard USD session caps
      * Persistent Self-Evolving Immunity Genome + 65-Signature Enterprise Genome Pack
      * Unwatermarked SOC2 / EU AI Act Signed Compliance Certificates
      * Mid-Session Rug-Pull Schema Drift Interactive Diff & Re-Pin Approval
  - ENTERPRISE ($9,800 Commercial / $24,800 Full IP Buyout: SENTRY-V3-ENT-...):
      * All Pro entitlements + Multi-Tenant Fleet enforcement, White-Label Redistribution rights,
        and custom SIEM/OTLP signed ledger export.
"""

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


PAYPAL_PRO_URL = "https://www.paypal.com/ncp/payment/7G6M6X7889A2Q"
BUYOUT_CONSOLE_URL = "https://pingguye.cn/stackverdict/agentwall"

# Verification salt & derived root verifier (paired with private keygen_master.py stored outside repo)
_VERIFIER_SALT = b"MCP_SENTRY_V3_SOVEREIGN_GUARD_2026_SALT"
_ROOT_SEED = b"SENTRY_V3_MASTER_VERIFY_ANCHOR_9F8E7D6C5B4A3210"


@dataclass
class LicenseStatus:
    valid: bool
    tier: str = "COMMUNITY"  # "COMMUNITY", "PRO", "ENTERPRISE"
    licensee: str = "Unlicensed Evaluation"
    expires_at: str = "EVAL"
    raw_key: str = ""
    reason: str = "Running in Free Community Evaluation Mode"
    quotas: Dict[str, int] = field(default_factory=dict)

    @property
    def is_paid(self) -> bool:
        return self.valid and self.tier in ("PRO", "ENTERPRISE")


def _compute_token_mac(tier: str, expiry: str, licensee_tag: str) -> str:
    payload = f"SENTRY-V3::{tier.upper()}::{expiry}::{licensee_tag.upper()}".encode("utf-8")
    derived = hashlib.pbkdf2_hmac("sha256", _ROOT_SEED, _VERIFIER_SALT + payload, 12000)
    return derived.hex()[:16].upper()


def verify_license_key(raw_key: Optional[str] = None) -> LicenseStatus:
    """
    Verifies a license key from argument, `MCP_SENTRY_LICENSE` env var, or `~/.mcp-sentry/license.key`.
    Format: SENTRY-V3-<TIER>-<YYYYMMDD|PERPETUAL>-<TAG>-<16HEX_MAC>
    """
    key = (raw_key or os.environ.get("MCP_SENTRY_LICENSE") or "").strip()
    if not key:
        default_path = os.path.join(os.path.expanduser("~"), ".mcp-sentry", "license.key")
        if os.path.exists(default_path):
            try:
                with open(default_path, "r", encoding="utf-8") as f:
                    key = f.read().strip()
            except Exception:
                key = ""

    community_quotas = {
        "max_shadow_snapshots_per_session": 1,
        "max_payload_diet_compressions_per_session": 3,
        "max_evolved_rules_per_session": 3,
        "allow_persistent_genome": 0,
        "allow_unwatermarked_soc2": 0,
        "allow_interactive_schema_repin": 0,
    }

    if not key:
        return LicenseStatus(
            valid=False,
            tier="COMMUNITY",
            quotas=community_quotas,
        )

    parts = key.split("-")
    # Expected: ["SENTRY", "V3", TIER, EXPIRY, TAG, MAC]
    if len(parts) != 6 or parts[0] != "SENTRY" or parts[1] != "V3":
        return LicenseStatus(
            valid=False,
            tier="COMMUNITY",
            raw_key=key,
            reason="Malformed license key format",
            quotas=community_quotas,
        )

    _, _, tier, expiry, tag, provided_mac = parts
    tier = tier.upper()
    if tier not in ("PRO", "ENT", "ENTERPRISE"):
        return LicenseStatus(
            valid=False,
            tier="COMMUNITY",
            raw_key=key,
            reason=f"Unknown license tier '{tier}'",
            quotas=community_quotas,
        )

    normalized_tier = "ENTERPRISE" if tier in ("ENT", "ENTERPRISE") else "PRO"
    expected_mac = _compute_token_mac(tier, expiry, tag)
    if not hmac.compare_digest(provided_mac.upper(), expected_mac):
        return LicenseStatus(
            valid=False,
            tier="COMMUNITY",
            raw_key=key,
            reason="Cryptographic signature mismatch on license key",
            quotas=community_quotas,
        )

    if expiry != "PERPETUAL":
        today = time.strftime("%Y%m%d", time.gmtime())
        if today > expiry:
            return LicenseStatus(
                valid=False,
                tier="COMMUNITY",
                raw_key=key,
                reason=f"License expired on {expiry}",
                quotas=community_quotas,
            )

    paid_quotas = {
        "max_shadow_snapshots_per_session": 999999,
        "max_payload_diet_compressions_per_session": 999999,
        "max_evolved_rules_per_session": 999999,
        "allow_persistent_genome": 1,
        "allow_unwatermarked_soc2": 1,
        "allow_interactive_schema_repin": 1,
    }
    return LicenseStatus(
        valid=True,
        tier=normalized_tier,
        licensee=tag,
        expires_at=expiry,
        raw_key=key,
        reason=f"Verified {normalized_tier} License ({tag})",
        quotas=paid_quotas,
    )
