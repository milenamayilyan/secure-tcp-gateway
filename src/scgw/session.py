"""Session object and manager (current + short-lived previous session for rekey overlap)."""
from __future__ import annotations

import threading
import time
from typing import List, Optional

from .crypto import KeyMaterial, RxState, TxState


class Session:
    def __init__(self, role: str, km: KeyMaterial, transcript_hash: bytes,
                 max_age: float = 7200.0) -> None:
        assert role in ("initiator", "responder")
        self.role = role
        self.id = transcript_hash[:8].hex()
        if role == "initiator":
            self.tx = TxState(km.key_i2r, km.fixed_i2r)
            self.rx = RxState(km.key_r2i, km.fixed_r2i)
        else:
            self.tx = TxState(km.key_r2i, km.fixed_r2i)
            self.rx = RxState(km.key_i2r, km.fixed_i2r)
        self.created = time.monotonic()
        self.max_age = max_age

    def age(self) -> float:
        return time.monotonic() - self.created

    def valid(self) -> bool:
        return self.age() < self.max_age


class SessionManager:
    def __init__(self, grace: float = 30.0) -> None:
        self._lock = threading.Lock()
        self._current: Optional[Session] = None
        self._previous: Optional[Session] = None
        self._prev_until = 0.0
        self._grace = grace

    def install(self, s: Session) -> None:
        with self._lock:
            self._previous, self._current = self._current, s
            self._prev_until = time.monotonic() + self._grace

    def current(self) -> Optional[Session]:
        with self._lock:
            return self._current

    def tx_session(self) -> Optional[Session]:
        s = self.current()
        return s if s is not None and s.valid() else None

    def rx_sessions(self) -> List[Session]:
        with self._lock:
            out = [s for s in (self._current,) if s is not None and s.valid()]
            if self._previous is not None and time.monotonic() < self._prev_until and self._previous.valid():
                out.append(self._previous)
            return out
