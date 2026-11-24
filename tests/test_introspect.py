"""Token introspection + revocation + global logout (steal item 2).

Every IdP in the scanned matrix (Keycloak, Auth0, Ory, Zitadel) exposes
RFC 7662 introspection and RFC 7009 revocation. This repo's JWTs are
self-contained — good for verification, bad for the stolen-phone story:
an issued access token stays valid for its whole 15-minute TTL and
nothing can pull it back.

Three pieces:
- POST /introspect (RFC 7662): {"active": bool, claims...} — never an
  error for bad tokens; requires a bearer token so anonymous probes
  can't harvest token validity.
- POST /revoke (RFC 7009): denylists the token's JTI (access tokens now
  check the denylist too); always 200, never leaks validity.
- POST /admin/users/{name}/revoke-all (global logout, the Keycloak/
  Zitadel "Remote/Global Logout API"): records a revocation watermark —
  every token that user got BEFORE the call stops verifying; tokens
  issued after keep working.
"""

import pytest


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    return TestClient(create_app(key_store=KeyStore(initial_secret="k")))


def login(u="alice", p="wonderland"):
    from fastapi.testclient import TestClient

    from auth_gateway.app import create_app
    from auth_gateway.keys import KeyStore

    c = TestClient(create_app(key_store=KeyStore(initial_secret="k")))
    return c, c.post("/token", json={"username": u, "password": p}).json()


def test_introspect_active_token(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    r = client.post(
        "/introspect",
        json={"token": tokens["access_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    body = r.json()
    assert r.status_code == 200 and body["active"] is True
    assert body["sub"] == "alice" and body["tenant"] == "acme"


def test_introspect_bad_tokens_are_inactive_never_errors(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    for bad in ["", "garbage", "a.b.c", tokens["access_token"][:-3] + "xxx"]:
        r = client.post("/introspect", json={"token": bad}, headers=h)
        assert r.status_code == 200
        assert r.json() == {"active": False}


def test_introspect_requires_auth(client):
    assert client.post("/introspect", json={"token": "x"}).status_code == 401


def test_revoke_kills_access_token_everywhere(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    # the caller (bob) must hold a DIFFERENT token: revoking your own
    # bearer kills your next call too
    bob = client.post("/token", json={"username": "bob", "password": "builder"}).json()
    h_bob = {"Authorization": f"Bearer {bob['access_token']}"}
    assert (
        client.post(
            "/revoke", json={"token": tokens["access_token"]}, headers=h_bob
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        ).status_code
        == 401
    )  # enforced
    body = client.post(
        "/introspect", json={"token": tokens["access_token"]}, headers=h_bob
    ).json()
    assert body["active"] is False


def test_revoke_never_leaks_validity(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (
        client.post("/revoke", json={"token": "garbage"}, headers=h).status_code == 200
    )
    assert client.post("/revoke", json={"token": ""}, headers=h).status_code == 200


def test_revoke_used_refresh_token_is_inactive(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    rotated = client.post(
        "/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).json()
    # the ORIGINAL refresh token was consumed by the rotation
    body = client.post(
        "/introspect",
        json={"token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {rotated['access_token']}"},
    ).json()
    assert body["active"] is False
    body2 = client.post(
        "/introspect",
        json={"token": rotated["refresh_token"]},
        headers={"Authorization": f"Bearer {rotated['access_token']}"},
    ).json()
    assert body2["active"] is True


def test_revoke_all_is_a_watermark_not_a_block(client):
    c, first = login()
    admin = c.post("/token", json={"username": "admin", "password": "sekret"}).json()
    r = c.post(
        "/admin/users/alice/revoke-all",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert r.status_code == 200
    # pre-watermark token dead...
    assert (
        c.get(
            "/me", headers={"Authorization": f"Bearer {first['access_token']}"}
        ).status_code
        == 401
    )
    assert (
        c.post("/refresh", json={"refresh_token": first["refresh_token"]}).status_code
        == 401
    )
    # ...but alice can log straight back in, and bob is untouched
    fresh = c.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    assert (
        c.get(
            "/me", headers={"Authorization": f"Bearer {fresh['access_token']}"}
        ).status_code
        == 200
    )
    bob = c.post("/token", json={"username": "bob", "password": "builder"}).json()
    assert (
        c.get(
            "/me", headers={"Authorization": f"Bearer {bob['access_token']}"}
        ).status_code
        == 200
    )


def test_revoke_all_requires_admin_scope(client):
    tokens = client.post(
        "/token", json={"username": "alice", "password": "wonderland"}
    ).json()
    r = client.post(
        "/admin/users/bob/revoke-all",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r.status_code == 403


def test_revoke_all_unknown_user_is_404(client):
    admin = client.post(
        "/token", json={"username": "admin", "password": "sekret"}
    ).json()
    r = client.post(
        "/admin/users/ghost/revoke-all",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert r.status_code == 404
