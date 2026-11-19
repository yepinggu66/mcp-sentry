"""
Deterministic Infinite-Loop & Session Budget Circuit Breaker for MCP Agents.
Prevents runaway token/API credit burn with O(1) sliding window tracking.
"""

import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass
class BudgetState:
    allowed: bool
    reason: str = ""
    session_calls: int = 0
    calls_last_minute: int = 0
    identical_calls_in_window: int = 0


class CircuitBreaker:
    def __init__(
        self,
        max_identical_calls: int = 3,
        window_seconds: float = 60.0,
        max_session_calls: int = 200,
        max_calls_per_minute: int = 60,
    ):
        self.max_identical_calls = max_identical_calls
        self.window_seconds = window_seconds
        self.max_session_calls = max_session_calls
        self.max_calls_per_minute = max_calls_per_minute

        self._call_history: Dict[str, deque] = {}
        self._session_minute_window: Dict[str, deque] = {}
        self._session_totals: Dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _fingerprint(session_id: str, tool_name: str, arguments: Any) -> str:
        arg_str = json.dumps(arguments, sort_keys=True, ensure_ascii=False) if arguments else ""
        return hashlib.sha256(f"{session_id}::{tool_name}::{arg_str}".encode("utf-8")).hexdigest()

    def check_and_record(
        self, tool_name: str, arguments: Any, session_id: str = "default"
    ) -> BudgetState:
        now = time.time()
        fp = self._fingerprint(session_id, tool_name, arguments)

        with self._lock:
            # 1. Session total budget check
            total = self._session_totals.get(session_id, 0)
            if total >= self.max_session_calls:
                return BudgetState(
                    allowed=False,
                    reason=f"Session call budget exhausted ({total}/{self.max_session_calls} calls)",
                    session_calls=total,
                )

            # 2. Per-minute sliding rate limit
            min_dq = self._session_minute_window.setdefault(session_id, deque())
            while min_dq and now - min_dq[0] > 60.0:
                min_dq.popleft()
            if len(min_dq) >= self.max_calls_per_minute:
                return BudgetState(
                    allowed=False,
                    reason=f"Rate limit exceeded ({len(min_dq)}/{self.max_calls_per_minute} calls/min)",
                    session_calls=total,
                    calls_last_minute=len(min_dq),
                )

            # 3. Identical-call infinite loop check
            dq = self._call_history.setdefault(fp, deque())
            while dq and now - dq[0] > self.window_seconds:
                dq.popleft()
            if len(dq) >= self.max_identical_calls:
                return BudgetState(
                    allowed=False,
                    reason=f"Infinite loop detected: '{tool_name}' called {len(dq)} identical times within {self.window_seconds}s",
                    session_calls=total,
                    calls_last_minute=len(min_dq),
                    identical_calls_in_window=len(dq),
                )

            # Record allowed call
            dq.append(now)
            min_dq.append(now)
            self._session_totals[session_id] = total + 1

            return BudgetState(
                allowed=True,
                session_calls=total + 1,
                calls_last_minute=len(min_dq),
                identical_calls_in_window=len(dq),
            )
