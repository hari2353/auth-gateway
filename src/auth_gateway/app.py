import secrets
import time
import uuid

from fastapi import FastAPI, HTTPException, Request

from .jwt_util import InvalidToken, sign, verify
from .keys import KeyStore
from .users import authenticate

ACCESS_TTL = 15 * 60
REFRESH_TTL = 12 * 3600


def create_app(key_store: KeyStore | None = None) -> FastAPI:
    store = key_store or KeyStore()
    revoked_refresh: set[str] = set()

    app = FastAPI(title="Auth Gateway", version="0.1.0")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    def issue_claims(base: dict, ttl: int, token_type: str) -> dict:
        now = int(time.time())
        claims = dict(base)
        claims.update(
            {
                "iss": "auth-gateway",
                "iat": now,
                "exp": now + ttl,
                "jti": uuid.uuid4().hex,
                "typ": token_type,
            }
        )
        return claims

    def issue_pair(base: dict) -> dict:
        kid, secret = store.active()
        access = sign(issue_claims(base, ACCESS_TTL, "access"), secret, kid)
        refresh = sign(issue_claims(base, REFRESH_TTL, "refresh"), secret, kid)
        return {"access_token": access, "refresh_token": refresh, "token_type": "bearer", "expires_in": ACCESS_TTL}

    def bearer_claims(request: Request, expected_type: str = "access") -> dict:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            claims = verify(header.removeprefix("Bearer ").strip(), store.get)
        except InvalidToken as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        if claims.get("typ") != expected_type:
            raise HTTPException(status_code=401, detail=f"expected {expected_type} token")
        return claims

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/token")
    def token(payload: dict) -> dict:
        username = str(payload.get("username", ""))[:256]
        password = str(payload.get("password", ""))[:1024]
        principal = authenticate(username, password)
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return issue_pair(principal)

    @app.post("/refresh")
    def refresh(payload: dict) -> dict:
        raw = str(payload.get("refresh_token", ""))
        try:
            claims = verify(raw, store.get)
        except InvalidToken as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        if claims.get("typ") != "refresh":
            raise HTTPException(status_code=401, detail="not a refresh token")
        jti = claims.get("jti", "")
        if jti in revoked_refresh:
            raise HTTPException(status_code=401, detail="refresh token already used")
        revoked_refresh.add(jti)
        base = {"sub": claims.get("sub"), "tenant": claims.get("tenant"), "scopes": claims.get("scopes")}
        return issue_pair(base)

    @app.get("/me")
    def me(request: Request) -> dict:
        claims = bearer_claims(request)
        return {"sub": claims.get("sub"), "tenant": claims.get("tenant"), "scopes": claims.get("scopes")}

    @app.get("/v1/tenants/{tenant_id}/profile")
    def tenant_profile(tenant_id: str, request: Request) -> dict:
        claims = bearer_claims(request)
        if claims.get("tenant") != tenant_id:
            raise HTTPException(status_code=403, detail="cross-tenant access denied")
        return {"tenant": tenant_id, "requested_by": claims.get("sub")}

    @app.post("/admin/rotate")
    def rotate(request: Request) -> dict:
        claims = bearer_claims(request)
        if "admin" not in (claims.get("scopes") or []):
            raise HTTPException(status_code=403, detail="admin scope required")
        new_kid = store.rotate()
        return {"active_kid": new_kid, "kept_versions": store.version_count()}

    return app


app = create_app()
