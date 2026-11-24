def login(client, username="alice", password="wonderland"):
    return client.post("/token", json={"username": username, "password": password})


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_bad_credentials_401(client):
    assert (
        client.post(
            "/token", json={"username": "alice", "password": "nope"}
        ).status_code
        == 401
    )


def test_login_and_me(client):
    pair = login(client).json()
    me = client.get("/me", headers=auth_header(pair["access_token"])).json()
    assert me == {"sub": "alice", "tenant": "acme", "scopes": ["read", "write"]}


def test_me_requires_token(client):
    assert client.get("/me").status_code == 401
    assert (
        client.get("/me", headers=auth_header("garbage.token.here")).status_code == 401
    )


def test_refresh_token_cannot_access_me(client):
    pair = login(client).json()
    resp = client.get("/me", headers=auth_header(pair["refresh_token"]))
    assert resp.status_code == 401


def test_refresh_flow_rotates_and_revokes_old(client):
    pair = login(client).json()
    second = client.post(
        "/refresh", json={"refresh_token": pair["refresh_token"]}
    ).json()
    assert "access_token" in second
    reuse = client.post("/refresh", json={"refresh_token": pair["refresh_token"]})
    assert reuse.status_code == 401


def test_cross_tenant_access_denied(client):
    acme_pair = login(client, username="alice").json()
    resp = client.get(
        "/v1/tenants/globex/profile", headers=auth_header(acme_pair["access_token"])
    )
    assert resp.status_code == 403
    ok = client.get(
        "/v1/tenants/acme/profile", headers=auth_header(acme_pair["access_token"])
    )
    assert ok.json()["tenant"] == "acme"


def test_rotation_requires_admin(client):
    user_pair = login(client, username="bob", password="builder").json()
    denied = client.post(
        "/admin/rotate", headers=auth_header(user_pair["access_token"])
    )
    assert denied.status_code == 403

    admin_pair = client.post(
        "/token", json={"username": "admin", "password": "sekret"}
    ).json()
    allowed = client.post(
        "/admin/rotate", headers=auth_header(admin_pair["access_token"])
    ).json()
    assert allowed["active_kid"].startswith("k")
    old_token = user_pair["access_token"]
    still_valid = client.get("/me", headers=auth_header(old_token))
    assert still_valid.status_code == 200


def test_security_headers_present(client):
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
