"""Capability-based access control (agentic-ai ch.9 cross-pollination).

Complements the existing JWT/throttle/MFA stack: a request's granted
scopes are checked against the capability a route requires, so a token can
carry least-privilege scopes instead of an all-or-nothing role.
"""

from __future__ import annotations

from collections.abc import Iterable


class MissingScope(PermissionError):
    """Raised when a required capability is not granted."""


def parse_scopes(value: str | Iterable[str] | None) -> frozenset[str]:
    """Accept a space/comma string or an iterable of scope names."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        tokens = value.replace(",", " ").split()
    else:
        tokens = [str(item) for item in value]
    return frozenset(token for token in tokens if token)


def has_scope(granted: frozenset[str] | set[str] | str | None, required: str) -> bool:
    """A granted scope satisfies a requirement if it equals it or is a wildcard
    prefix: ``admin:*`` satisfies ``admin:keys`` and ``admin:users``."""
    granted_set = (
        parse_scopes(granted)
        if not isinstance(granted, (frozenset, set))
        else frozenset(granted)
    )
    if required in granted_set or "*" in granted_set:
        return True
    for scope in granted_set:
        if scope.endswith(":*"):
            prefix = scope[:-2]
            if required == prefix or required.startswith(prefix + ":"):
                return True
        if scope.endswith("*") and required.startswith(scope[:-1]):
            return True
    return False


def require_scope(granted, required: str) -> None:
    if not has_scope(granted, required):
        raise MissingScope(f"missing required scope: {required}")


def require_all(granted, required: Iterable[str]) -> None:
    for scope in required:
        require_scope(granted, scope)


def require_any(granted, required: Iterable[str]) -> None:
    if not any(has_scope(granted, scope) for scope in required):
        raise MissingScope(
            "missing one of required scopes: " + ", ".join(sorted(required))
        )
