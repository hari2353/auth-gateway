import secrets
import time


class KeyStore:
    def __init__(
        self, initial_secret: str | None = None, max_versions: int = 3
    ) -> None:
        self._versions: dict[str, tuple[str, float]] = {}
        self._counter = 0
        self.max_versions = max_versions
        self._active_kid = self.rotate(initial_secret or secrets.token_urlsafe(48))

    def rotate(self, secret: str | None = None) -> str:
        self._counter += 1
        kid = f"k{self._counter}"
        self._versions[kid] = (secret or secrets.token_urlsafe(48), time.time())
        self._purge_old()
        self._active_kid = kid
        return kid

    def _purge_old(self) -> None:
        while len(self._versions) > self.max_versions:
            oldest = min(self._versions, key=lambda k: self._versions[k][1])
            del self._versions[oldest]

    @property
    def active_kid(self) -> str:
        return self._active_kid

    def active(self) -> tuple[str, str]:
        secret = self._versions[self._active_kid][0]
        return self._active_kid, secret

    def get(self, kid: str | None) -> str | None:
        if kid is None or kid not in self._versions:
            return None
        return self._versions[kid][0]

    def version_count(self) -> int:
        return len(self._versions)
