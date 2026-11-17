"""Security audit events — Zitadel's pitch is an event-sourced core
("every state change permanently auditable"); Keycloak ships an event
log every admin can read. This repo produced exactly the right events
and wrote them nowhere. Bounded ring buffer (last MAX_EVENTS), newest
first, one dict per event — token-frugal by construction.
"""
import threading
import time
from collections import deque

MAX_EVENTS = 200


class AuditLog:
    def __init__(self, max_events: int = MAX_EVENTS) -> None:
        self._events: deque = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def record(self, event: str, user: str = "", **detail) -> None:
        entry = {"event": event, "user": user, "at": time.time()}
        # detail is flattened (with reserved keys protected) — one level,
        # no nested digging for consumers
        entry.update({k: v for k, v in detail.items()
                      if k not in ("event", "user", "at")})
        with self._lock:
            self._events.append(entry)

    def recent(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            return list(self._events)[-limit:][::-1]     # newest first

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


_log = AuditLog()


def record(event: str, user: str = "", **detail) -> None:
    _log.record(event, user, **detail)


def recent(limit: int = 100) -> list[dict]:
    return _log.recent(limit)


def clear() -> None:
    _log.clear()
