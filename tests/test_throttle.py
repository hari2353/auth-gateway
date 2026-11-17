"""Login throttling + account lockout (steal item 1).

Auth0 and Zitadel ship rate limiting built in; Keycloak's answer is a
reverse proxy; this repo's own SECURITY.md listed "no rate limiting /
lockout on /token" as a deliberate gap. Brute force is the one attack
that needs zero sophistication, and PBKDF2 at 100k iterations makes each
guess expensive for the SERVER too — an attacker gets a free DoS.

Pure stdlib: fixed-window counter per (username, client IP), lockout for
15 minutes after 5 failures, 429 + Retry-After so honest clients back
off, and a bounded counter dict (no unbounded memory from fuzzed
usernames).
"""
import time

import pytest


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="k")))


def creds(u="alice", p="wonderland"):
    return {"username": u, "password": p}


def test_burst_of_failures_locks_the_account(client, monkeypatch):
    for _ in range(5):
        r = client.post("/token", json=creds(p="wrong"))
        assert r.status_code == 401
    r = client.post("/token", json=creds())            # correct creds now
    assert r.status_code == 429
    assert r.headers["retry-after"].isdigit()
    assert "locked" in r.json()["detail"].lower()


def test_successful_login_resets_the_failure_counter(client):
    for _ in range(4):                                 # under the threshold
        client.post("/token", json=creds(p="wrong"))
    assert client.post("/token", json=creds()).status_code == 200
    for _ in range(4):                                 # counter was reset
        client.post("/token", json=creds(p="wrong"))
    assert client.post("/token", json=creds()).status_code == 200


def test_other_accounts_and_lockout_are_independent(client):
    for _ in range(5):
        client.post("/token", json=creds(p="wrong"))
    assert client.post("/token", json=creds(u="bob", p="builder")).status_code == 200
    assert client.post("/token", json=creds(p="wrong")).status_code == 429


def test_lockout_expires(client, monkeypatch):
    start = time.monotonic()
    t = {"now": start}
    monkeypatch.setattr(time, "monotonic", lambda: t["now"])
    for _ in range(5):
        client.post("/token", json=creds(p="wrong"))
    t["now"] = start + 901                             # past the 15-min window
    assert client.post("/token", json=creds()).status_code == 200


def test_counter_store_is_bounded(client):
    from auth_gateway.app import create_app
    from auth_gateway.throttle import Throttle

    th = Throttle(max_tracked=100)
    for i in range(500):
        th.failed(f"user{i}", "ip")
    assert len(th._failures) <= 100


def test_rate_limit_headers_on_lockout(client):
    for _ in range(5):
        client.post("/token", json=creds(p="wrong"))
    r = client.post("/token", json=creds())
    assert r.status_code == 429
    assert "no-store" in r.headers["cache-control"]   # 429s stay uncached
