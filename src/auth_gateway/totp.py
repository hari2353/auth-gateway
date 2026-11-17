"""Hand-rolled TOTP (RFC 6238) + recovery codes — the "Authenticator App"
MFA every IdP ships, built on the same ethos as the rest of this repo:
every moving part (HMAC, dynamic truncation, time-slicing, drift window)
is explicit stdlib and unit-tested against the RFC's own vectors.

Verification is constant-time (hmac.compare_digest) and accepts a +/-1
step (30s) of clock drift, like every production TOTP verifier.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

STEP = 30
DIGITS = 6
DRIFT = 1                # accepted clock drift, in steps


def generate_secret() -> str:
    """160-bit base32 secret (RFC 4226 recommended length)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_url(secret: str, username: str, issuer: str = "auth-gateway") -> str:
    """The URL every authenticator app (Google, Aegis, 1Password) scans."""
    from urllib.parse import quote

    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def code_at(secret: str, counter: int) -> str:
    """RFC 4226 HMAC-SHA1 + dynamic truncation, 6 digits."""
    key = base32_decode(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
    return f"{value % 10 ** DIGITS:0{DIGITS}d}"


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """True when the code matches the current step or a +/-DRIFT neighbor."""
    t = at if at is not None else time.time()
    counter = int(t // STEP)
    code = str(code or "").strip()
    if len(code) != DIGITS or not code.isdigit():
        return False
    for drift in range(-DRIFT, DRIFT + 1):
        if hmac.compare_digest(code_at(secret, counter + drift), code):
            return True
    return False


def generate_recovery_codes(n: int = 10) -> list[str]:
    """One-time codes in a human-transcribable xxxx-xxxx form."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]


def base32_decode(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
