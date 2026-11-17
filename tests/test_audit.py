"""Security audit events (steal item 4).

Zitadel's product pitch is its event-sourced core: "every state change
permanently auditable." Keycloak ships an event log (logins, failures,
admin actions) every admin can read. This repo produced exactly the
right events — login ok/fail, lockout, refresh reuse, key rotation —
and wrote them nowhere an admin could read.

audit.py: a bounded ring buffer (last 200) of structured events; every
security-relevant path records one; GET /admin/events reads it (admin
scope), newest first, bounded with ?limit.
"""
import pytest


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="k")))


def admin_client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    c = TestClient(create_app(key_store=KeyStore(initial_secret="k")))
    t = c.post("/token", json={"username": "admin", "password": "sekret"}).json()
    return c, {"Authorization": f"Bearer {t['access_token']}"}


def test_login_events_recorded(client):
    c, h = admin_client()
    c.post("/token", json={"username": "alice", "password": "wonderland"})
    c.post("/token", json={"username": "alice", "password": "wrong"})
    evts = c.get("/admin/events", headers=h).json()["events"]
    kinds = [e["event"] for e in evts]
    assert "login.ok" in kinds and "login.fail" in kinds
    ok = next(e for e in evts if e["event"] == "login.ok")
    assert ok["user"] == "alice" and ok["at"]


def test_lockout_and_mfa_events_recorded(client):
    from auth_gateway.totp import code_at
    import time

    c, h = admin_client()
    for _ in range(5):
        c.post("/token", json={"username": "bob", "password": "wrong"})
    kinds = [e["event"] for e in c.get("/admin/events", headers=h).json()["events"]]
    assert "account.locked" in kinds

    # mfa flow events
    r = c.post("/mfa/enroll", json={"username": "alice", "password": "wonderland"})
    secret = r.json()["secret"]
    c.post("/mfa/confirm", json={"username": "alice", "password": "wonderland",
                                 "code": code_at(secret, int(time.time() // 30))})
    kinds = [e["event"] for e in c.get("/admin/events", headers=h).json()["events"]]
    assert "mfa.enrolled" in kinds
    c.post("/token", json={"username": "alice", "password": "wonderland",
                           "totp_code": "000000"})
    kinds = [e["event"] for e in c.get("/admin/events", headers=h).json()["events"]]
    assert "mfa.fail" in kinds


def test_token_lifecycle_events_recorded(client):
    c, h = admin_client()
    t = c.post("/token", json={"username": "alice", "password": "wonderland"}).json()
    c.post("/refresh", json={"refresh_token": t["refresh_token"]})
    c.post("/refresh", json={"refresh_token": t["refresh_token"]})   # reuse
    c.post("/revoke", json={"token": t["access_token"]},
           headers={"Authorization": f"Bearer {t['access_token']}"})
    c.post("/admin/rotate", headers=h)
    kinds = [e["event"] for e in c.get("/admin/events", headers=h).json()["events"]]
    for expected in ("token.refreshed", "refresh.reuse", "token.revoked", "key.rotated"):
        assert expected in kinds, expected


def test_revoke_all_event_recorded(client):
    c, h = admin_client()
    c.post("/admin/users/bob/revoke-all", headers=h)
    evts = c.get("/admin/events", headers=h).json()["events"]
    ev = next(e for e in evts if e["event"] == "user.revoked_all")
    assert ev["user"] == "bob" and ev["by"] == "admin"


def test_events_endpoint_is_admin_only_and_bounded(client):
    c, h = admin_client()
    for i in range(230):                     # overflow the ring
        from auth_gateway.audit import record
        record("noise", user=f"u{i % 7}")
    assert c.get("/admin/events", headers=h).status_code == 200
    body = c.get("/admin/events?limit=50", headers=h).json()
    assert len(body["events"]) == 50
    alice = c.post("/token", json={"username": "alice", "password": "wonderland"}).json()
    r = c.get("/admin/events", headers={"Authorization": f"Bearer {alice['access_token']}"})
    assert r.status_code == 403
    assert c.get("/admin/events").status_code == 401


def test_events_newest_first(client):
    c, h = admin_client()
    c.post("/token", json={"username": "bob", "password": "builder"})
    c.post("/token", json={"username": "alice", "password": "wonderland"})
    evts = c.get("/admin/events?limit=2", headers=h).json()["events"]
    assert evts[0]["user"] == "alice" and evts[1]["user"] == "bob"
