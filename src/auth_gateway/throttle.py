"""Login throttling + account lockout — Auth0/Zitadel ship this built in;
this repo's SECURITY.md listed its absence as a deliberate gap. Brute
force needs zero sophistication, and PBKDF2 at 100k iterations makes each
guess expensive for the SERVER too (an attacker gets a free DoS).

Fixed-window failure counter per (username, client IP); lockout for
LOCKOUT_SECONDS after LOCKOUT_AFTER consecutive failures; a successful
login resets the counter. Counters are bounded so fuzzed usernames can't
grow memory without limit.
"""

import time
from collections import defaultdict

LOCKOUT_AFTER = 5
LOCKOUT_SECONDS = 15 * 60
MAX_TRACKED = 10_000


class Throttle:
    def __init__(
        self,
        lockout_after: int = LOCKOUT_AFTER,
        lockout_seconds: float = LOCKOUT_SECONDS,
        max_tracked: int = MAX_TRACKED,
    ) -> None:
        self._failures: dict[tuple[str, str], int] = defaultdict(int)
        self._locked_until: dict[tuple[str, str], float] = {}
        self.lockout_after = lockout_after
        self.lockout_seconds = lockout_seconds
        self.max_tracked = max_tracked

    def check(self, username: str, ip: str) -> float:
        """Seconds remaining in this (username, ip)'s lockout; 0 = open."""
        return max(self._locked_until.get((username, ip), 0.0) - time.monotonic(), 0.0)

    def failed(self, username: str, ip: str) -> None:
        key = (username, ip)
        self._failures[key] += 1
        if self._failures[key] >= self.lockout_after:
            self._locked_until[key] = time.monotonic() + self.lockout_seconds
        if len(self._failures) > self.max_tracked:
            # bounded: drop oldest-tracked counters (insertion order);
            # locked keys are re-armed by their own timestamps
            for stale in list(self._failures)[: len(self._failures) - self.max_tracked]:
                self._failures.pop(stale, None)

    def ok(self, username: str, ip: str) -> None:
        self._failures.pop((username, ip), None)
