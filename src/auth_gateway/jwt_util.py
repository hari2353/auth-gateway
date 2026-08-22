import base64
import hashlib
import hmac
import json
import time


class InvalidToken(Exception):
    pass


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def sign(claims: dict, secret: str, kid: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    encoded_header = _b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64u_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64u_encode(signature)}"


def verify(token: str, key_lookup) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("malformed token")
    encoded_header, encoded_payload, signature = parts
    try:
        header = json.loads(_b64u_decode(encoded_header))
    except (ValueError, json.JSONDecodeError):
        raise InvalidToken("undecodable header")
    if header.get("alg") != "HS256":
        raise InvalidToken("unsupported alg")
    secret = key_lookup(header.get("kid"))
    if secret is None:
        raise InvalidToken("unknown kid")
    expected = _b64u_encode(hmac.new(secret.encode(), f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        raise InvalidToken("bad signature")
    try:
        claims = json.loads(_b64u_decode(encoded_payload))
    except (ValueError, json.JSONDecodeError):
        raise InvalidToken("undecodable payload")
    exp = claims.get("exp")
    if exp is not None and time.time() > float(exp):
        raise InvalidToken("token expired")
    return claims
