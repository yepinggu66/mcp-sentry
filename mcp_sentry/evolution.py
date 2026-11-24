"""
MCP-Sentry v3.0 Evolutionary Defense & Practical ROI Engines:
  1. ShadowVault (⏪ Time-Machine Pre-Execution File Snapshot & 1-Click Auto-Rollback)
  2. TokenDietEngine (💰 Real-Time USD Cost Circuit Breaker & Smart Payload Diet Compressor)
  3. AdaptiveImmunityEngine (🧬 Self-Evolving Behavioral Immunity & Zero-Day Gene Synthesizer)
  4. CanaryHoneypot (🪤 Active Deception Canary Token Injector & Exfiltration Quarantine)

100% Pure Python stdlib (zero external dependencies).
"""

import hashlib
import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .license import BUYOUT_CONSOLE_URL, PAYPAL_PRO_URL, LicenseStatus, verify_license_key


MUTATING_TOOL_KEYWORDS = (
    "write",
    "edit",
    "delete",
    "remove",
    "patch",
    "replace",
    "create",
    "modify",
    "save",
    "update",
    "append",
    "truncate",
    "mv",
    "move",
)

PATH_ARG_CANDIDATES = (
    "path",
    "file_path",
    "filepath",
    "filename",
    "file",
    "target",
    "target_file",
    "destination",
    "dest",
)


# ============================================================================
# 1. ⏪ ShadowVault: Pre-Execution File Snapshot & 1-Click Session Rollback
# ============================================================================

@dataclass
class SnapshotRecord:
    session_id: str
    tool_name: str
    file_path: str
    existed_before: bool
    backup_blob_path: str
    sha256_before: str
    timestamp: float


class ShadowVault:
    """
    Captures zero-latency pre-execution file snapshots before mutating MCP tools run,
    allowing 1-second time-machine rollback when an AI agent corrupts code or loops.
    """

    def __init__(self, vault_dir: Optional[str] = None, license_status: Optional[LicenseStatus] = None):
        if not vault_dir:
            vault_dir = os.path.join(os.path.expanduser("~"), ".mcp-sentry", "shadow_vault")
        os.makedirs(vault_dir, exist_ok=True)
        self.vault_dir = vault_dir
        self.license_status = license_status or verify_license_key()
        self._lock = threading.Lock()
        self._session_counts: Dict[str, int] = {}

    @staticmethod
    def _extract_file_paths(tool_name: str, arguments: Any) -> List[str]:
        if not isinstance(arguments, dict):
            return []
        tlower = tool_name.lower()
        is_mutating = any(k in tlower for k in MUTATING_TOOL_KEYWORDS)
        paths: List[str] = []
        for k, v in arguments.items():
            if isinstance(v, str) and (k.lower() in PATH_ARG_CANDIDATES or is_mutating):
                candidate = v.strip()
                if candidate and not candidate.startswith(("http://", "https://")) and len(candidate) < 512:
                    if os.path.exists(candidate) or is_mutating:
                        paths.append(os.path.abspath(candidate))
        return paths

    def snapshot_before_call(
        self, tool_name: str, arguments: Any, session_id: str = "default"
    ) -> Tuple[List[SnapshotRecord], Optional[str]]:
        """
        Snapshots target files before a mutating tool executes.
        Returns (records_created, commercial_notice_if_quota_reached).
        """
        target_paths = self._extract_file_paths(tool_name, arguments)
        if not target_paths:
            return [], None

        max_quota = self.license_status.quotas.get("max_shadow_snapshots_per_session", 1)
        created: List[SnapshotRecord] = []
        notice: Optional[str] = None

        with self._lock:
            sess_dir = os.path.join(self.vault_dir, session_id)
            os.makedirs(sess_dir, exist_ok=True)
            manifest_path = os.path.join(sess_dir, "manifest.json")
            manifest: List[Dict[str, Any]] = []
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                except Exception:
                    manifest = []

            already_tracked = {item["file_path"] for item in manifest}
            used = self._session_counts.get(session_id, len(already_tracked))

            for fpath in target_paths:
                if fpath in already_tracked:
                    continue
                if used >= max_quota and not self.license_status.is_paid:
                    notice = (
                        f"[MCP-Sentry ShadowVault EVAL LIMIT] Free Community tier protects {max_quota} file/session. "
                        f"File '{os.path.basename(fpath)}' was NOT snapshotted. Unlock Unlimited Time-Machine Rollbacks ($49 Pro): {PAYPAL_PRO_URL}"
                    )
                    break

                existed = os.path.isfile(fpath)
                sha_before = ""
                blob_path = ""
                if existed:
                    try:
                        with open(fpath, "rb") as src:
                            raw = src.read()
                        sha_before = hashlib.sha256(raw).hexdigest()
                        blob_name = f"{len(manifest):04d}_{sha_before[:12]}.blob"
                        blob_path = os.path.join(sess_dir, blob_name)
                        with open(blob_path, "wb") as dst:
                            dst.write(raw)
                    except Exception:
                        continue

                rec = SnapshotRecord(
                    session_id=session_id,
                    tool_name=tool_name,
                    file_path=fpath,
                    existed_before=existed,
                    backup_blob_path=blob_path,
                    sha256_before=sha_before,
                    timestamp=time.time(),
                )
                created.append(rec)
                manifest.append(
                    {
                        "session_id": rec.session_id,
                        "tool_name": rec.tool_name,
                        "file_path": rec.file_path,
                        "existed_before": rec.existed_before,
                        "backup_blob_path": rec.backup_blob_path,
                        "sha256_before": rec.sha256_before,
                        "timestamp": rec.timestamp,
                    }
                )
                already_tracked.add(fpath)
                used += 1

            self._session_counts[session_id] = used
            if created:
                with open(manifest_path, "w", encoding="utf-8") as f:
                    json.dump(manifest, f, indent=2, ensure_ascii=False)

        return created, notice

    def rollback_session(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Restores all snapshotted files in `session_id` (or latest session if None)
        to their exact pre-agent bytes.
        """
        with self._lock:
            if not session_id:
                sessions = [
                    d for d in os.listdir(self.vault_dir)
                    if os.path.isdir(os.path.join(self.vault_dir, d))
                ]
                if not sessions:
                    return {"ok": False, "restored_files": [], "message": "No ShadowVault snapshots found."}
                sessions.sort(
                    key=lambda d: os.path.getmtime(os.path.join(self.vault_dir, d)),
                    reverse=True,
                )
                session_id = sessions[0]

            sess_dir = os.path.join(self.vault_dir, session_id)
            manifest_path = os.path.join(sess_dir, "manifest.json")
            if not os.path.exists(manifest_path):
                return {"ok": False, "session_id": session_id, "restored_files": [], "message": f"No manifest for session '{session_id}'."}

            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            restored: List[str] = []
            removed_new: List[str] = []
            # Restore in reverse chronological order
            for entry in reversed(manifest):
                fpath = entry["file_path"]
                if entry["existed_before"]:
                    blob = entry["backup_blob_path"]
                    if blob and os.path.exists(blob):
                        os.makedirs(os.path.dirname(fpath), exist_ok=True)
                        shutil.copyfile(blob, fpath)
                        restored.append(fpath)
                else:
                    if os.path.isfile(fpath):
                        try:
                            os.remove(fpath)
                            removed_new.append(fpath)
                        except Exception:
                            pass

            return {
                "ok": True,
                "session_id": session_id,
                "restored_files": restored,
                "removed_created_files": removed_new,
                "total_recovered": len(restored) + len(removed_new),
                "message": f"Time-Machine Rollback complete for session '{session_id}': restored {len(restored)} files, cleaned {len(removed_new)} AI-created files.",
            }

    def list_sessions(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(self.vault_dir):
            return out
        for d in os.listdir(self.vault_dir):
            mpath = os.path.join(self.vault_dir, d, "manifest.json")
            if os.path.isfile(mpath):
                try:
                    with open(mpath, "r", encoding="utf-8") as f:
                        items = json.load(f)
                    out.append(
                        {
                            "session_id": d,
                            "files_protected": len(items),
                            "files": [os.path.basename(x["file_path"]) for x in items],
                        }
                    )
                except Exception:
                    pass
        return out


# ============================================================================
# 2. 💰 TokenDietEngine: Real-Time USD Budget Breaker & Smart Payload Diet
# ============================================================================

@dataclass
class TokenCostMetrics:
    allowed: bool
    reason: str = ""
    session_tokens_used: int = 0
    session_usd_burned: float = 0.0
    session_tokens_saved: int = 0
    session_usd_saved: float = 0.0
    diet_applied: bool = False
    commercial_notice: str = ""


class TokenDietEngine:
    """
    Calculates real-time LLM token & USD burn across MCP tool calls and responses.
    Automatically compresses bloated MCP outputs (Smart Payload Diet) to save 50%-80% API spend,
    and trips a hard USD budget breaker before runaway agents drain API credits.
    """

    def __init__(
        self,
        max_session_usd: float = 5.00,
        max_response_chars: int = 6000,
        usd_per_1k_tokens: float = 0.015,
        enable_payload_diet: bool = True,
        license_status: Optional[LicenseStatus] = None,
    ):
        self.max_session_usd = max_session_usd
        self.max_response_chars = max_response_chars
        self.usd_per_1k_tokens = usd_per_1k_tokens
        self.enable_payload_diet = enable_payload_diet
        self.license_status = license_status or verify_license_key()

        self._lock = threading.Lock()
        self._tokens_used: Dict[str, int] = {}
        self._tokens_saved: Dict[str, int] = {}
        self._diet_count: Dict[str, int] = {}

    @staticmethod
    def estimate_tokens(text: str) -> int:
        if not text:
            return 0
        return max(1, (len(text) + 3) // 4)

    def _tokens_to_usd(self, tokens: int) -> float:
        return round((tokens / 1000.0) * self.usd_per_1k_tokens, 4)

    def check_and_account_request(
        self, tool_name: str, arguments: Any, session_id: str = "default"
    ) -> TokenCostMetrics:
        raw = json.dumps(arguments, ensure_ascii=False) if arguments else ""
        req_tokens = self.estimate_tokens(raw) + 25  # tool invocation overhead

        with self._lock:
            cur_used = self._tokens_used.get(session_id, 0)
            cur_saved = self._tokens_saved.get(session_id, 0)
            projected_tokens = cur_used + req_tokens
            projected_usd = self._tokens_to_usd(projected_tokens)

            if self.max_session_usd > 0 and projected_usd > self.max_session_usd:
                return TokenCostMetrics(
                    allowed=False,
                    reason=(
                        f"USD Budget Circuit Breaker tripped on '{tool_name}': session spend "
                        f"${projected_usd:.4f} exceeds max_session_usd cap (${self.max_session_usd:.2f})"
                    ),
                    session_tokens_used=cur_used,
                    session_usd_burned=self._tokens_to_usd(cur_used),
                    session_tokens_saved=cur_saved,
                    session_usd_saved=self._tokens_to_usd(cur_saved),
                )

            self._tokens_used[session_id] = projected_tokens
            return TokenCostMetrics(
                allowed=True,
                session_tokens_used=projected_tokens,
                session_usd_burned=projected_usd,
                session_tokens_saved=cur_saved,
                session_usd_saved=self._tokens_to_usd(cur_saved),
            )

    def inspect_and_compress_response(
        self, tool_name: str, result_obj: Any, session_id: str = "default"
    ) -> Tuple[Any, TokenCostMetrics]:
        """
        Accounts for outbound tool response tokens and applies Smart Payload Diet
        if the response exceeds `max_response_chars`.
        """
        raw = json.dumps(result_obj, ensure_ascii=False)
        orig_tokens = self.estimate_tokens(raw)
        max_quota = self.license_status.quotas.get("max_payload_diet_compressions_per_session", 3)

        with self._lock:
            used_diets = self._diet_count.get(session_id, 0)
            diet_applied = False
            notice = ""
            saved_tokens = 0
            new_result = result_obj

            if self.enable_payload_diet and len(raw) > self.max_response_chars:
                potential_saved_chars = len(raw) - self.max_response_chars
                potential_saved_tokens = self.estimate_tokens("x" * potential_saved_chars)
                potential_saved_usd = self._tokens_to_usd(potential_saved_tokens)

                if self.license_status.is_paid or used_diets < max_quota:
                    new_result = self._compress_result_object(result_obj, self.max_response_chars, potential_saved_tokens, potential_saved_usd)
                    compressed_raw = json.dumps(new_result, ensure_ascii=False)
                    new_tokens = self.estimate_tokens(compressed_raw)
                    saved_tokens = max(0, orig_tokens - new_tokens)
                    orig_tokens = new_tokens
                    diet_applied = True
                    self._diet_count[session_id] = used_diets + 1
                else:
                    notice = (
                        f"[MCP-Sentry Smart Diet EVAL LIMIT] Bloated response from '{tool_name}' ({len(raw):,} chars) "
                        f"burned ${potential_saved_usd:.4f} extra API credits. Free tier includes {max_quota} compressions/session. "
                        f"Unlock Unlimited Token Diet ($49 Pro): {PAYPAL_PRO_URL}"
                    )

            total_used = self._tokens_used.get(session_id, 0) + orig_tokens
            total_saved = self._tokens_saved.get(session_id, 0) + saved_tokens
            self._tokens_used[session_id] = total_used
            self._tokens_saved[session_id] = total_saved

            return new_result, TokenCostMetrics(
                allowed=True,
                session_tokens_used=total_used,
                session_usd_burned=self._tokens_to_usd(total_used),
                session_tokens_saved=total_saved,
                session_usd_saved=self._tokens_to_usd(total_saved),
                diet_applied=diet_applied,
                commercial_notice=notice,
            )

    @staticmethod
    def _compress_result_object(
        result_obj: Any, max_chars: int, saved_tokens: int, saved_usd: float
    ) -> Any:
        head_len = int(max_chars * 0.65)
        tail_len = int(max_chars * 0.25)
        marker = (
            f"\n...[⚡ MCP-Sentry Smart Payload Diet: trimmed bloated middle output | "
            f"Saved ~{saved_tokens:,} tokens (${saved_usd:.4f} USD)]...\n"
        )

        if isinstance(result_obj, dict) and isinstance(result_obj.get("content"), list):
            new_content = []
            for item in result_obj["content"]:
                if isinstance(item, dict) and isinstance(item.get("text"), str) and len(item["text"]) > max_chars:
                    txt = item["text"]
                    trimmed = txt[:head_len] + marker + txt[-tail_len:]
                    new_item = dict(item)
                    new_item["text"] = trimmed
                    new_content.append(new_item)
                else:
                    new_content.append(item)
            out = dict(result_obj)
            out["content"] = new_content
            return out

        raw_str = json.dumps(result_obj, ensure_ascii=False)
        if len(raw_str) > max_chars:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": raw_str[:head_len] + marker + raw_str[-tail_len:],
                    }
                ]
            }
        return result_obj

    def get_totals(self) -> Dict[str, Any]:
        with self._lock:
            tot_used = sum(self._tokens_used.values())
            tot_saved = sum(self._tokens_saved.values())
            return {
                "total_tokens_used": tot_used,
                "total_usd_burned": self._tokens_to_usd(tot_used),
                "total_tokens_saved": tot_saved,
                "total_usd_saved": self._tokens_to_usd(tot_saved),
                "total_compressions": sum(self._diet_count.values()),
            }


# ============================================================================
# 3. 🧬 AdaptiveImmunityEngine: Self-Evolving Behavioral Immunity
# ============================================================================

@dataclass
class ImmunityGene:
    gene_id: str
    tool_name: str
    arg_keys: List[str]
    signature_token: str
    category: str
    severity: str
    created_at: str


class AdaptiveImmunityEngine:
    """
    Self-Evolving Behavioral Immunity Engine.
    Automatically extracts structural AST/payload genes from blocked attacks or HITL denials
    so the firewall mutates and immunizes itself against future variants automatically.
    """

    DANGEROUS_TOKEN_EXTRACTOR = re.compile(
        r"(/etc/[a-zA-Z0-9_.\-]+|/var/run/[a-zA-Z0-9_.\-]+|\.[a-zA-Z0-9_]+/id_[a-zA-Z0-9]+|"
        r"169\.254\.169\.254|--privileged|--pid=host|COPY\s+.*\s+TO\s+PROGRAM|"
        r"pg_read_file|lo_export|DROP\s+TABLE|TRUNCATE\s+TABLE|rm\s+-[rf]+|/dev/tcp/)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        genome_path: Optional[str] = None,
        license_status: Optional[LicenseStatus] = None,
    ):
        if not genome_path:
            genome_path = os.path.join(os.path.expanduser("~"), ".mcp-sentry", "immunity_genome.json")
        self.genome_path = genome_path
        self.license_status = license_status or verify_license_key()
        self._lock = threading.Lock()
        self._genes: Dict[str, ImmunityGene] = {}
        self._load_persisted_genome()

    def _load_persisted_genome(self):
        if not self.license_status.is_paid:
            return
        if self.genome_path and os.path.exists(self.genome_path):
            try:
                with open(self.genome_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for g in data.get("genes", []):
                    gene = ImmunityGene(
                        gene_id=g["gene_id"],
                        tool_name=g.get("tool_name", "*"),
                        arg_keys=g.get("arg_keys", []),
                        signature_token=g["signature_token"],
                        category=g.get("category", "ADAPTIVE_IMMUNITY"),
                        severity=g.get("severity", "CRITICAL"),
                        created_at=g.get("created_at", ""),
                    )
                    self._genes[gene.gene_id] = gene
            except Exception:
                pass

    def evolve_from_incident(
        self, tool_name: str, arguments: Any, category: str, severity: str = "CRITICAL"
    ) -> Tuple[Optional[ImmunityGene], Optional[str]]:
        """
        Synthesizes a new ImmunityGene from a blocked or operator-denied tool call.
        Returns (new_gene, commercial_notice_if_eval_capped).
        """
        raw_args = json.dumps(arguments, sort_keys=True, ensure_ascii=False) if arguments else ""
        arg_keys = sorted(list(arguments.keys())) if isinstance(arguments, dict) else []

        match = self.DANGEROUS_TOKEN_EXTRACTOR.search(raw_args)
        if match:
            sig_token = match.group(0).lower()
        else:
            # Extract structural command prefix / suspicious token skeleton
            cleaned = re.sub(r"\s+", " ", raw_args).strip()
            sig_token = cleaned[:48].lower() if cleaned else tool_name.lower()

        digest = hashlib.sha256(f"{tool_name}::{','.join(arg_keys)}::{sig_token}".encode("utf-8")).hexdigest()[:8].upper()
        gene_id = f"GENE-{digest}"

        max_quota = self.license_status.quotas.get("max_evolved_rules_per_session", 3)
        notice: Optional[str] = None

        with self._lock:
            if gene_id in self._genes:
                return self._genes[gene_id], None

            if not self.license_status.is_paid and len(self._genes) >= max_quota:
                notice = (
                    f"[MCP-Sentry Self-Evolving Immunity EVAL LIMIT] Reached {max_quota} in-memory evolved genes. "
                    f"Unlock Persistent Self-Evolving Genome & 65-Signature Enterprise Pack ($49 Pro): {PAYPAL_PRO_URL}"
                )
                return None, notice

            gene = ImmunityGene(
                gene_id=gene_id,
                tool_name=tool_name,
                arg_keys=arg_keys,
                signature_token=sig_token,
                category=f"EVOLVED_{category}",
                severity=severity,
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
            self._genes[gene_id] = gene

            if self.license_status.is_paid:
                self._persist_locked()
            else:
                notice = (
                    f"[MCP-Sentry Immunity Evolved] Synthesized {gene_id} in-memory. "
                    f"(Note: Free mode does not persist evolved genes across restarts — Activate Pro to persist)"
                )

            return gene, notice

    def _persist_locked(self):
        if not self.genome_path:
            return
        try:
            os.makedirs(os.path.dirname(self.genome_path), exist_ok=True)
            payload = {
                "genome_version": "3.0.0",
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "genes": [
                    {
                        "gene_id": g.gene_id,
                        "tool_name": g.tool_name,
                        "arg_keys": g.arg_keys,
                        "signature_token": g.signature_token,
                        "category": g.category,
                        "severity": g.severity,
                        "created_at": g.created_at,
                    }
                    for g in self._genes.values()
                ],
            }
            with open(self.genome_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def inspect_call(self, tool_name: str, arguments: Any) -> Optional[ImmunityGene]:
        """Checks if an incoming tool call matches any evolved immunity gene."""
        raw_args = (json.dumps(arguments, sort_keys=True, ensure_ascii=False) if arguments else "").lower()
        with self._lock:
            for gene in self._genes.values():
                if gene.tool_name in ("*", tool_name) and gene.signature_token and gene.signature_token in raw_args:
                    return gene
        return None

    def list_genes(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "gene_id": g.gene_id,
                    "tool_name": g.tool_name,
                    "arg_keys": g.arg_keys,
                    "signature_token": g.signature_token,
                    "category": g.category,
                    "severity": g.severity,
                    "created_at": g.created_at,
                }
                for g in self._genes.values()
            ]


# ============================================================================
# 4. 🪤 CanaryHoneypot: Active Deception Canary Token Trap
# ============================================================================

class CanaryHoneypot:
    """
    Active Deception Honeypot Engine.
    Generates deterministic watermarked Canary Credentials (fake OpenAI / AWS / Stripe tokens)
    to bait poisoned or untrusted MCP tools. If any outbound tool ever attempts to transmit
    a planted canary token, the session is caught red-handed with 0% false positives.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._active_canaries: Dict[str, str] = {}  # canary_token -> session_id
        self._quarantined_sessions: Set[str] = set()

    def mint_canary_env(self, session_id: str = "default") -> Dict[str, str]:
        tag = hashlib.sha256(f"CANARY::{session_id}".encode("utf-8")).hexdigest()[:16].upper()
        openai_canary = f"sk-proj-SENTRYCANARY{tag}99887766"
        aws_canary = f"AKIASENTRY{tag[:10]}"
        with self._lock:
            self._active_canaries[openai_canary] = session_id
            self._active_canaries[aws_canary] = session_id
        return {
            "OPENAI_API_KEY": openai_canary,
            "AWS_ACCESS_KEY_ID": aws_canary,
            "honeypot_payload": f"OPENAI_API_KEY={openai_canary}\nAWS_ACCESS_KEY_ID={aws_canary}\n",
        }

    def inspect_for_canary_exfil(self, tool_name: str, arguments: Any, session_id: str = "default") -> Tuple[bool, str]:
        """
        Returns (triggered, reason). If true, the agent/server tried to exfiltrate a honeypot canary token!
        """
        raw = json.dumps(arguments, ensure_ascii=False) if arguments else ""
        with self._lock:
            if session_id in self._quarantined_sessions:
                return True, f"Session '{session_id}' is permanently quarantined due to prior Canary Honeypot exfiltration."
            for token, origin_sess in self._active_canaries.items():
                if token in raw:
                    self._quarantined_sessions.add(session_id)
                    return (
                        True,
                        f"Active Honeypot Canary Trap triggered! Tool '{tool_name}' attempted to exfiltrate planted decoy credential '{token[:22]}...' (origin={origin_sess}). Session quarantined.",
                    )
        return False, ""
