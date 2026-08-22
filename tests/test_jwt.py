import time

import pytest

from auth_gateway.jwt_util import InvalidToken, sign, verify
from auth_gateway.keys import KeyStore


def test_sign_and_verify_roundtrip():
    store = KeyStore(initial_secret="s")
    kid, secret = store.active()
    token = sign({"sub": "a", "exp": time.time() + 60}, secret, kid)
    claims = verify(token, store.get)
    assert claims["sub"] == "a"


def test_tampered_payload_rejected():
    store = KeyStore(initial_secret="s")
    kid, secret = store.active()
    token = sign({"sub": "a", "exp": time.time() + 60}, secret, kid)
    header, payload, sig = token.split(".")
    forged_payload = payload[:-2] + ("AA" if not payload.endswith("AA") else "BB")
    with pytest.raises(InvalidToken):
        verify(f"{header}.{forged_payload}.{sig}", store.get)


def test_expired_token_rejected():
    store = KeyStore(initial_secret="s")
    kid, secret = store.active()
    token = sign({"sub": "a", "exp": time.time() - 10}, secret, kid)
    with pytest.raises(InvalidToken, match="expired"):
        verify(token, store.get)


def test_unknown_kid_rejected():
    store = KeyStore(initial_secret="s")
    token = sign({"sub": "a"}, "some-other-secret", "k999")
    with pytest.raises(InvalidToken, match="kid"):
        verify(token, store.get)


def test_rotation_keeps_old_tokens_verifiable_within_window():
    store = KeyStore(initial_secret="s1", max_versions=3)
    kid_old, _ = store.active()
    old_token = sign({"sub": "a"}, store.get(kid_old), kid_old)
    new_kid = store.rotate()
    assert new_kid != kid_old
    assert verify(old_token, store.get)["sub"] == "a"
    kid_active, secret_active = store.active()
    assert kid_active == new_kid
    new_token = sign({"sub": "b"}, secret_active, kid_active)
    assert verify(new_token, store.get)["sub"] == "b"


def test_purges_beyond_max_versions():
    store = KeyStore(initial_secret="s0", max_versions=2)
    first_kid = store.active_kid
    store.rotate()
    store.rotate()
    assert store.version_count() <= 2
    assert store.get(first_kid) is None
