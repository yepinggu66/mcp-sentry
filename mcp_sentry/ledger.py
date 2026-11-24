"""
Tamper-Evident Cryptographic Audit Ledger (Hash-Chained + HMAC-SHA256 Signed).
Outputs both JSONL (for SIEM / OpenTelemetry pipelines) and SQLite (for fast queries).
Designed for SOC2, ISO 27001, and EU AI Act compliance verification.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


GENESIS_HASH = "0" * 64


class AuditLedger:
    def __init__(
        self,
        log_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
        jsonl_path: Optional[str] = None,
    ):
        if not log_dir:
            log_dir = os.path.join(os.path.expanduser("~"), ".mcp-sentry")
        os.makedirs(log_dir, exist_ok=True)

        self.log_dir = log_dir
        self.jsonl_path = jsonl_path or os.path.join(log_dir, "audit_ledger.jsonl")
        self.db_path = os.path.join(log_dir, "audit_ledger.db")
        self.signing_key = (
            signing_key or os.environ.get("MCP_SENTRY_SIGNING_KEY") or "mcp-sentry-local-dev-key"
        ).encode("utf-8")

        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        self._seq = 0
        self._init_db()
        self._recover_chain_head()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    action TEXT NOT NULL,
                    category TEXT,
                    severity TEXT,
                    reason TEXT,
                    latency_ms REAL,
                    payload_json TEXT,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _recover_chain_head(self):
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT seq, entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row:
                self._seq = int(row[0])
                self._last_hash = str(row[1])
        finally:
            conn.close()

    def _compute_hash_and_sig(self, record: Dict[str, Any]) -> Tuple[str, str]:
        canonical = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()
        sig = hmac.new(self.signing_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        return entry_hash, sig

    def record(
        self,
        event_type: str,
        action: str,
        tool_name: str = "",
        category: str = "CLEAN",
        severity: str = "INFO",
        reason: str = "",
        latency_ms: float = 0.0,
        session_id: str = "default",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._seq += 1
            base_record = {
                "seq": self._seq,
                "timestamp": ts,
                "session_id": session_id,
                "event_type": event_type,
                "tool_name": tool_name,
                "action": action,
                "category": category,
                "severity": severity,
                "reason": reason,
                "latency_ms": round(latency_ms, 3),
                "payload": payload or {},
                "prev_hash": self._last_hash,
            }
            entry_hash, signature = self._compute_hash_and_sig(base_record)
            full_record = dict(base_record)
            full_record["entry_hash"] = entry_hash
            full_record["signature"] = signature
            self._last_hash = entry_hash

            # Append to JSONL
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(full_record, ensure_ascii=False) + "\n")
            except Exception:
                pass

            # Persist to SQLite
            try:
                conn = sqlite3.connect(self.db_path)
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        seq, timestamp, session_id, event_type, tool_name,
                        action, category, severity, reason, latency_ms,
                        payload_json, prev_hash, entry_hash, signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._seq,
                        ts,
                        session_id,
                        event_type,
                        tool_name,
                        action,
                        category,
                        severity,
                        reason,
                        round(latency_ms, 3),
                        json.dumps(payload or {}, ensure_ascii=False),
                        base_record["prev_hash"],
                        entry_hash,
                        signature,
                    ),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

            return full_record

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT seq, timestamp, session_id, event_type, tool_name,
                       action, category, severity, reason, latency_ms, entry_hash
                FROM audit_events ORDER BY seq DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [
                {
                    "seq": r[0],
                    "timestamp": r[1],
                    "session_id": r[2],
                    "event_type": r[3],
                    "tool_name": r[4],
                    "action": r[5],
                    "category": r[6],
                    "severity": r[7],
                    "reason": r[8],
                    "latency_ms": r[9],
                    "entry_hash": r[10],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def verify_chain(self) -> Tuple[bool, int, str]:
        """
        Cryptographically verifies every event in the JSONL ledger.
        Returns (is_valid, verified_count, detail_message).
        """
        if not os.path.exists(self.jsonl_path):
            return True, 0, "Ledger is empty (0 entries)."

        expected_prev = GENESIS_HASH
        count = 0
        with open(self.jsonl_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception as e:
                    return False, count, f"Corrupt JSON at line {line_no}: {e}"

                if entry.get("prev_hash") != expected_prev:
                    return (
                        False,
                        count,
                        f"Hash chain broken at seq {entry.get('seq')} (line {line_no}): expected prev_hash {expected_prev[:12]}, got {str(entry.get('prev_hash'))[:12]}",
                    )

                claimed_hash = entry.pop("entry_hash", "")
                claimed_sig = entry.pop("signature", "")
                actual_hash, actual_sig = self._compute_hash_and_sig(entry)

                if claimed_hash != actual_hash:
                    return (
                        False,
                        count,
                        f"Entry tampered at seq {entry.get('seq')} (line {line_no}): SHA-256 mismatch",
                    )
                if not hmac.compare_digest(claimed_sig, actual_sig):
                    return (
                        False,
                        count,
                        f"Signature invalid at seq {entry.get('seq')} (line {line_no}): HMAC mismatch",
                    )

                expected_prev = actual_hash
                count += 1

        return True, count, f"Cryptographic verification PASSED ({count} chained & signed entries intact)."

    def export_soc2_html(self, license_status: Optional[Any] = None) -> str:
        """
        Generates a self-contained SOC2 / ISO27001 / EU AI Act Cryptographic Audit Dossier in HTML.
        Unlicensed Community mode applies a visible [UNLICENSED EVALUATION] watermark + upgrade CTA.
        """
        from .license import BUYOUT_CONSOLE_URL, PAYPAL_PRO_URL, verify_license_key

        lic = license_status or verify_license_key()
        valid, count, msg = self.verify_chain()
        events = self.recent_events(100)
        head_hash = events[0]["entry_hash"] if events else GENESIS_HASH
        blocked_count = sum(1 for e in events if e["action"] == "BLOCK")

        if lic.is_paid:
            banner_html = f"""
            <div style="background:#064e3b;border:1px solid #10b981;color:#a7f3d0;padding:14px 20px;border-radius:8px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;">
              <div><strong>VERIFIED COMMERCIAL COMPLIANCE CERTIFICATE</strong> — Licensed to <code>{lic.licensee}</code> ({lic.tier})</div>
              <span style="background:#10b981;color:#022c22;padding:4px 10px;border-radius:99px;font-weight:800;font-size:12px;">SOC2 &amp; EU AI ACT READY</span>
            </div>"""
        else:
            banner_html = f"""
            <div style="background:#450a0a;border:2px dashed #ef4444;color:#fecaca;padding:16px 20px;border-radius:10px;margin-bottom:20px;">
              <div style="font-size:15px;font-weight:800;color:#f87171;">⚠️ UNLICENSED EVALUATION WATERMARK — NOT VALID FOR EXTERNAL COMPLIANCE AUDIT</div>
              <div style="margin-top:6px;font-size:13px;">Remove evaluation watermarks, unlock persistent Self-Evolving Immunity Genome, and enable unlimited Time-Machine Rollbacks:</div>
              <div style="margin-top:12px;">
                <a href="{PAYPAL_PRO_URL}" style="background:#10b981;color:#022c22;padding:8px 14px;border-radius:6px;text-decoration:none;font-weight:800;font-size:13px;margin-right:10px;">⚡ Unlock Pro License ($49 One-Time)</a>
                <a href="{BUYOUT_CONSOLE_URL}" style="background:#3b82f6;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;font-weight:800;font-size:13px;">🏛️ Full IP &amp; Turnkey Buyout ($30,000)</a>
              </div>
            </div>"""

        rows_html = "".join(
            f"<tr><td>#{e['seq']}</td><td>{e['timestamp']}</td><td><strong>{e['action']}</strong></td>"
            f"<td>{e['category']}</td><td><code>{e['tool_name'] or '-'}</code></td><td>{e['reason'] or '-'}</td>"
            f"<td><code>{e['entry_hash'][:16]}…</code></td></tr>"
            for e in events
        )

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>MCP-Sentry v3.0 — Cryptographic SOC2 &amp; EU AI Act Audit Dossier</title>
<style>
  body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background:#0b1120; color:#e2e8f0; margin:24px; }}
  .box {{ max-width:1100px; margin:0 auto; background:#111827; border:1px solid #1f2937; border-radius:12px; padding:24px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:16px; font-size:12px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937; }}
  th {{ background:#0f172a; color:#94a3b8; }}
</style></head><body><div class="box">
  {banner_html}
  <h1 style="margin:0 0 8px;font-size:20px;">🛡️ MCP-Sentry v3.0 — Cryptographic Audit Ledger Report</h1>
  <p style="color:#94a3b8;font-size:13px;margin:0 0 16px;">Chain Status: <strong>{'PASSED' if valid else 'FAILED'}</strong> ({msg}) | Chain Head SHA-256: <code>{head_hash}</code> | Total Entries: {count} | Threats Blocked: {blocked_count}</p>
  <table><thead><tr><th>Seq</th><th>Timestamp</th><th>Action</th><th>Category</th><th>Tool</th><th>Reason</th><th>SHA-256 Chain Hash</th></tr></thead>
  <tbody>{rows_html or '<tr><td colspan="7">No events recorded yet.</td></tr>'}</tbody></table>
</div></body></html>"""

