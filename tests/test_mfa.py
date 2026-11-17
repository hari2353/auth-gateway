"""Hand-rolled TOTP MFA + recovery codes (steal item 3).

Every IdP in the matrix ships TOTP ("Authenticator App") plus one-time
recovery codes; NIST SP 800-63-4 still lists TOTP as a reasonable AAL2
authenticator. This repo's identity is "hand-rolled to demonstrate
depth" — TOTP is RFC 4226 truncation + RFC 6238 time-slicing over hmac
+ hashlib: ~50 lines of stdlib, no pyotp.

Keycloak's flow, adapted: enroll (credentials) -> pending secret +
otpauth:// URL -> confirm with a real code from the authenticator ->
active, 10 one-time recovery codes issued exactly once. /token then
requires totp_code or recovery_code after the password check (MFA
state is never revealed to password-less callers). Admins get
mfa-reset (Keycloak's "Reset OTP" required action).
"""
import time

import pytest

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32("12345678901234567890")
RFC_VECTORS = [(59, "287082"), (1111111109, "081804"), (1234567890, "005924")]


# ---------------------------------------------------------------- unit: RFC 6238
def test_totp_matches_rfc6238_vectors():
    from auth_gateway.totp import code_at

    for ts, expected in RFC_VECTORS:
        assert code_at(RFC_SECRET, ts // 30) == expected, f"t={ts}"


def test_verify_accepts_current_and_neighbor_steps():
    from auth_gateway.totp import code_at, verify

    now = 1_700_000_000
    current = code_at(RFC_SECRET, now // 30)
    neighbor = code_at(RFC_SECRET, now // 30 - 1)
    assert verify(RFC_SECRET, current, at=now) is True
    assert verify(RFC_SECRET, neighbor, at=now) is True       # clock drift
    assert verify(RFC_SECRET, "000000", at=now) is False or code_at(RFC_SECRET, now // 30) == "000000"
    assert verify(RFC_SECRET, "12345", at=now) is False       # malformed


def test_verify_is_constant_time_compared(monkeypatch):
    import hmac as hmac_mod

    from auth_gateway import totp

    seen = {}
    real = hmac_mod.compare_digest
    monkeypatch.setattr(totp.hmac, "compare_digest",
                        lambda a, b: seen.setdefault("cmp", True) and real(a, b))
    totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, 1_700_000_000 // 30),
                at=1_700_000_000)
    assert seen.get("cmp") is True


def test_secret_and_codes_shape():
    from auth_gateway.totp import generate_recovery_codes, generate_secret

    s = generate_secret()
    assert len(s) == 32 and s.isupper()          # 160 bits, base32
    codes = generate_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(len(c) == 9 and "-" in c for c in codes)


# ---------------------------------------------------------------- enroll flow
@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="k")))


CREDS = {"username": "alice", "password": "wonderland"}


def _enroll_and_confirm(c):
    from auth_gateway.totp import code_at

    r = c.post("/mfa/enroll", json=CREDS)
    secret = r.json()["secret"]
    code = code_at(secret, int(time.time() // 30))
    conf = c.post("/mfa/confirm", json={**CREDS, "code": code})
    return secret, conf.json()


def test_enroll_returns_secret_and_otpauth_url(client):
    r = client.post("/mfa/enroll", json=CREDS)
    assert r.status_code == 200
    body = r.json()
    assert body["secret"].isupper() and len(body["secret"]) == 32
    assert body["otpauth_url"].startswith("otpauth://totp/")
    assert "secret=" in body["otpauth_url"] and "issuer=auth-gateway" in body["otpauth_url"]


def test_confirm_activates_mfa_and_issues_recovery_codes_once(client):
    _, body = _enroll_and_confirm(client)
    assert len(body["recovery_codes"]) == 10
    # confirming again does NOT re-issue codes
    from auth_gateway.totp import code_at

    from auth_gateway.users import USERS

    secret = USERS["alice"]["totp_secret"]
    again = client.post("/mfa/confirm", json={**CREDS, "code": code_at(secret, int(time.time() // 30))})
    assert "recovery_codes" not in again.json() or not again.json().get("recovery_codes")


def test_token_requires_mfa_once_enrolled(client):
    from auth_gateway.totp import code_at

    secret, _ = _enroll_and_confirm(client)
    r = client.post("/token", json=CREDS)
    assert r.status_code == 401 and "mfa" in r.json()["detail"].lower()
    code = code_at(secret, int(time.time() // 30))
    ok = client.post("/token", json={**CREDS, "totp_code": code})
    assert ok.status_code == 200 and "access_token" in ok.json()


def test_wrong_totp_is_401(client):
    secret, _ = _enroll_and_confirm(client)
    r = client.post("/token", json={**CREDS, "totp_code": "000000"})
    assert r.status_code == 401
    if secret == "x":
        pytest.fail("unreachable")


def test_recovery_code_single_use(client):
    from auth_gateway.totp import code_at

    secret, body = _enroll_and_confirm(client)
    rc = body["recovery_codes"][0]
    assert client.post("/token", json={**CREDS, "recovery_code": rc}).status_code == 200
    assert client.post("/token", json={**CREDS, "recovery_code": rc}).status_code == 401
    # totp still works after a recovery-code login
    code = code_at(secret, int(time.time() // 30))
    assert client.post("/token", json={**CREDS, "totp_code": code}).status_code == 200


def test_mfa_enroll_requires_valid_credentials(client):
    r = client.post("/mfa/enroll", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    r2 = client.post("/mfa/enroll", json={"username": "ghost", "password": "x"})
    assert r2.status_code == 401


def test_admin_mfa_reset(client):
    from auth_gateway.totp import code_at

    _enroll_and_confirm(client)
    admin = client.post("/token", json={"username": "admin", "password": "sekret"}).json()
    r = client.post("/admin/users/alice/mfa-reset",
                    headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert r.status_code == 200
    assert client.post("/token", json=CREDS).status_code == 200   # no code needed


def test_admin_mfa_reset_requires_admin(client):
    _enroll_and_confirm(client)
    alice = client.post("/token", json=CREDS)  # 401: mfa required, no token
    assert alice.status_code == 401
    admin = client.post("/token", json={"username": "admin", "password": "sekret"}).json()
    r = client.post("/admin/users/alice/mfa-reset",
                    headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert r.status_code == 200
    # a non-admin bearer can't reset
    bob = client.post("/token", json={"username": "bob", "password": "builder"}).json()
    r2 = client.post("/admin/users/bob/mfa-reset",
                     headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert r2.status_code == 403
