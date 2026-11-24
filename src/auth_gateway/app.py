import secrets
import time
import uuid

from fastapi import FastAPI, HTTPException, Request

from . import audit
from .jwt_util import InvalidToken, sign, verify
from .keys import KeyStore
from .throttle import Throttle
from .totp import generate_recovery_codes, generate_secret, otpauth_url
from .totp import verify as totp_verify
from .users import USERS, authenticate

ACCESS_TTL = 15 * 60
REFRESH_TTL = 12 * 3600


def create_app(key_store: KeyStore | None = None) -> FastAPI:
    store = key_store or KeyStore()
    revoked_refresh: set[str] = set()
    revoked_access: set[str] = set()
    revoked_before: dict[str, float] = {}  # user -> iat watermark (global logout)
    throttle = Throttle()

    app = FastAPI(title="Auth Gateway", version="0.2.0")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    def issue_claims(base: dict, ttl: int, token_type: str) -> dict:
        # float iat (RFC 7519 NumericDate allows fractions): sub-second
        # resolution is what makes the revoke-all watermark exact
        now = time.time()
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
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": ACCESS_TTL,
        }

    def bearer_claims(request: Request, expected_type: str = "access") -> dict:
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            claims = verify(header.removeprefix("Bearer ").strip(), store.get)
        except InvalidToken as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        if claims.get("typ") != expected_type:
            raise HTTPException(
                status_code=401, detail=f"expected {expected_type} token"
            )
        if claims.get("jti", "") in revoked_access:
            raise HTTPException(status_code=401, detail="token revoked")
        if claims.get("iat", 0) < revoked_before.get(claims.get("sub", ""), 0):
            raise HTTPException(
                status_code=401, detail="token revoked by administrator"
            )
        return claims

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    def password_gate(payload: dict, request: Request) -> dict:
        """Shared credential+throttle check for /token and the MFA flow."""
        username = str(payload.get("username", ""))[:256]
        password = str(payload.get("password", ""))[:1024]
        ip = request.client.host if request.client else ""
        remaining = throttle.check(username, ip)
        if remaining > 0:
            audit.record("account.locked", username, ip=ip, retry_after=int(remaining))
            raise HTTPException(
                status_code=429,
                detail=f"account locked; retry in {int(remaining) // 60 + 1} minute(s)",
                headers={"Retry-After": str(int(remaining) + 1)},
            )
        principal = authenticate(username, password)
        if principal is None:
            throttle.failed(username, ip)
            if throttle.check(username, ip) > 0:
                audit.record("account.locked", username, ip=ip)
            audit.record("login.fail", username, ip=ip)
            raise HTTPException(status_code=401, detail="invalid credentials")
        throttle.ok(username, ip)
        return principal

    def mfa_satisfied(payload: dict, request: Request, username: str) -> bool:
        """True when the request carries a valid TOTP or unused recovery
        code. A WRONG code counts toward lockout like any failed login."""
        record = USERS.get(username) or {}
        secret = record.get("totp_secret")
        if not secret:
            return True  # not enrolled
        totp_code = str(payload.get("totp_code", "") or "").strip()
        if totp_code and totp_verify(secret, totp_code):
            return True
        recovery = str(payload.get("recovery_code", "") or "").strip()
        if (
            recovery
            and recovery in record.get("recovery_codes", [])
            and recovery not in record["recovery_used"]
        ):
            record["recovery_used"].add(recovery)
            return True
        if totp_code or recovery:
            throttle.failed(username, request.client.host if request.client else "")
            audit.record("mfa.fail", username)
            raise HTTPException(status_code=401, detail="invalid mfa code")
        return False

    @app.post("/token")
    def token(payload: dict, request: Request) -> dict:
        principal = password_gate(payload, request)
        if not mfa_satisfied(payload, request, principal["sub"]):
            raise HTTPException(status_code=401, detail="mfa required")
        audit.record("login.ok", principal["sub"])
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
            audit.record("refresh.reuse", claims.get("sub", ""))
            raise HTTPException(status_code=401, detail="refresh token already used")
        if claims.get("iat", 0) < revoked_before.get(claims.get("sub", ""), 0):
            raise HTTPException(
                status_code=401, detail="refresh token revoked by administrator"
            )
        revoked_refresh.add(jti)
        audit.record("token.refreshed", claims.get("sub", ""))
        base = {
            "sub": claims.get("sub"),
            "tenant": claims.get("tenant"),
            "scopes": claims.get("scopes"),
        }
        return issue_pair(base)

    @app.get("/me")
    def me(request: Request) -> dict:
        claims = bearer_claims(request)
        return {
            "sub": claims.get("sub"),
            "tenant": claims.get("tenant"),
            "scopes": claims.get("scopes"),
        }

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
        audit.record("key.rotated", claims.get("sub", ""), kid=new_kid)
        return {"active_kid": new_kid, "kept_versions": store.version_count()}

    @app.post("/mfa/enroll")
    def mfa_enroll(payload: dict, request: Request) -> dict:
        """Step 1 of Keycloak's Configure-OTP flow: valid credentials buy a
        pending secret + otpauth:// URL; nothing is active yet."""
        principal = password_gate(payload, request)
        record = USERS[principal["sub"]]
        secret = generate_secret()
        record["totp_pending"] = secret
        return {"secret": secret, "otpauth_url": otpauth_url(secret, principal["sub"])}

    @app.post("/mfa/confirm")
    def mfa_confirm(payload: dict, request: Request) -> dict:
        """Step 2: a code from the real authenticator activates MFA and
        issues 10 one-time recovery codes exactly once. Re-confirming an
        already-enrolled user verifies but never re-issues codes."""
        principal = password_gate(payload, request)
        record = USERS[principal["sub"]]
        code = str(payload.get("code", "") or "")
        if record.get("totp_secret"):
            if not totp_verify(record["totp_secret"], code):
                throttle.failed(
                    principal["sub"], request.client.host if request.client else ""
                )
                raise HTTPException(status_code=401, detail="invalid mfa code")
            return {"status": "already enrolled"}
        pending = record.get("totp_pending")
        if not pending:
            raise HTTPException(status_code=409, detail="no pending enrollment")
        if not totp_verify(pending, code):
            throttle.failed(
                principal["sub"], request.client.host if request.client else ""
            )
            raise HTTPException(status_code=401, detail="invalid mfa code")
        record["totp_secret"] = pending
        record["totp_pending"] = None
        record["recovery_codes"] = generate_recovery_codes()
        record["recovery_used"] = set()
        audit.record("mfa.enrolled", principal["sub"])
        return {"status": "enrolled", "recovery_codes": list(record["recovery_codes"])}

    @app.post("/admin/users/{name}/mfa-reset")
    def mfa_reset(name: str, request: Request) -> dict:
        """Keycloak's Reset-OTP required action: clears the factor; the
        user logs in with password only and can re-enroll."""
        claims = bearer_claims(request)
        if "admin" not in (claims.get("scopes") or []):
            raise HTTPException(status_code=403, detail="admin scope required")
        if name not in USERS:
            raise HTTPException(status_code=404, detail="unknown user")
        for key in ("totp_secret", "totp_pending"):
            USERS[name][key] = None
        USERS[name]["recovery_codes"] = []
        USERS[name]["recovery_used"] = set()
        audit.record("mfa.reset", name, by=claims.get("sub", ""))
        return {"user": name, "mfa": "reset"}

    @app.get("/admin/events")
    def events(limit: int = 100, request: Request = None) -> dict:
        claims = bearer_claims(request)
        if "admin" not in (claims.get("scopes") or []):
            raise HTTPException(status_code=403, detail="admin scope required")
        return {"events": audit.recent(limit)}

    @app.post("/introspect")
    def introspect(payload: dict, request: Request) -> dict:
        """RFC 7662: bad/expired/revoked tokens are {"active": false},
        never an error. Caller must hold a valid token so anonymous
        probes can't harvest token validity."""
        bearer_claims(request)
        raw = str(payload.get("token", ""))[:8192]
        try:
            claims = verify(raw, store.get)
        except InvalidToken:
            return {"active": False}
        jti, sub, iat = (
            claims.get("jti", ""),
            claims.get("sub", ""),
            claims.get("iat", 0),
        )
        if claims.get("typ") not in ("access", "refresh"):
            return {"active": False}
        if jti in revoked_access or jti in revoked_refresh:
            return {"active": False}
        if iat < revoked_before.get(sub, 0):
            return {"active": False}
        return {
            "active": True,
            "sub": sub,
            "tenant": claims.get("tenant"),
            "scopes": claims.get("scopes"),
            "exp": claims.get("exp"),
            "token_type": claims.get("typ"),
        }

    @app.post("/revoke")
    def revoke(payload: dict, request: Request) -> dict:
        """RFC 7009: always 200 — the response never leaks whether the
        token existed or was already revoked."""
        bearer_claims(request)
        raw = str(payload.get("token", ""))[:8192]
        try:
            claims = verify(raw, store.get)
        except InvalidToken:
            return {"revoked": True}
        jti = claims.get("jti", "")
        if claims.get("typ") == "access":
            revoked_access.add(jti)
        elif claims.get("typ") == "refresh":
            revoked_refresh.add(jti)
        audit.record("token.revoked", claims.get("sub", ""), typ=claims.get("typ"))
        return {"revoked": True}

    @app.post("/admin/users/{name}/revoke-all")
    def revoke_all(name: str, request: Request) -> dict:
        """Global logout (Keycloak/Zitadel Remote Logout): a revocation
        watermark — every token this user got BEFORE this call stops
        verifying; fresh logins work immediately."""
        claims = bearer_claims(request)
        if "admin" not in (claims.get("scopes") or []):
            raise HTTPException(status_code=403, detail="admin scope required")
        if name not in USERS:
            raise HTTPException(status_code=404, detail="unknown user")
        watermark = time.time()  # float: sub-second, fail-closed —
        revoked_before[name] = watermark  # same-second tokens are revoked too
        audit.record("user.revoked_all", name, by=claims.get("sub", ""))
        return {"user": name, "revoked_before": watermark}

    return app


app = create_app()
