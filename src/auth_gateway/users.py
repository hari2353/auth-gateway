import hashlib
import secrets

_ITERATIONS = 100_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), _ITERATIONS)
        return secrets.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


USERS = {
    "alice": {"password_hash": hash_password("wonderland"), "tenant": "acme", "scopes": ["read", "write"],
              "totp_secret": None, "totp_pending": None, "recovery_codes": [], "recovery_used": set()},
    "admin": {"password_hash": hash_password("sekret"), "tenant": "root", "scopes": ["read", "write", "admin"],
              "totp_secret": None, "totp_pending": None, "recovery_codes": [], "recovery_used": set()},
    "bob": {"password_hash": hash_password("builder"), "tenant": "globex", "scopes": ["read"],
            "totp_secret": None, "totp_pending": None, "recovery_codes": [], "recovery_used": set()},
}


def authenticate(username: str, password: str) -> dict | None:
    record = USERS.get(username)
    if record is None or not verify_password(password, record["password_hash"]):
        return None
    return {"sub": username, "tenant": record["tenant"], "scopes": record["scopes"]}
