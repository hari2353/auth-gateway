# Auth Gateway

[![ci](https://github.com/hari2353/auth-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/hari2353/auth-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A dependency-light OAuth2-style authentication service in FastAPI: **hand-rolled HS256 JWTs** (no `pyjwt`),
versioned signing keys with **zero-downtime rotation**, refresh-token reuse detection, and strict
**cross-tenant object-level authorization**.

Built to demonstrate the security patterns behind enterprise SSO fleets: kid-keyed verification,
`hmac.compare_digest` everywhere, PBKDF2 password hashing (stdlib only), denylisted refresh JTIs,
and security headers on every response.

## Why hand-rolled JWT?

Not for production use — for **demonstrating depth**. Every moving part (b64url encoding, kid lookup,
alg pinning, exp checking) is explicit and unit-tested. Swap `jwt_util.sign/verify` for `pyjwt` in one file
if you deploy it.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/token` | credentials (+ TOTP/recovery code once MFA is enrolled) | returns access (15 min) + refresh (12 h) pair; throttled, 429+Retry-After after 5 failures |
| POST | `/refresh` | refresh token | rotates pair; old JTI revoked (reuse = 401) |
| GET | `/me` | access token | echoes subject, tenant, scopes |
| GET | `/v1/tenants/{tenant_id}/profile` | access token | **403 on tenant mismatch** |
| POST | `/mfa/enroll` → `/mfa/confirm` | credentials | RFC 6238 TOTP: pending secret + otpauth:// URL, then confirm with a real code → active + 10 one-time recovery codes |
| POST | `/introspect` | access token | RFC 7662: `{"active": bool, claims...}` — never an error for bad tokens |
| POST | `/revoke` | access token | RFC 7009: always 200; access JTIs join a denylist enforced everywhere |
| POST | `/admin/rotate` | admin scope | new signing key; old tokens stay valid within retention window |
| POST | `/admin/users/{name}/revoke-all` | admin scope | global logout: iat watermark kills every pre-call token; fresh logins work immediately |
| POST | `/admin/users/{name}/mfa-reset` | admin scope | clears the user's TOTP factor (Keycloak's Reset-OTP) |
| GET | `/admin/events` | admin scope | bounded audit ring (last 200), newest first, `?limit` |

## Key rotation story

`KeyStore` keeps a bounded version window (`max_versions`). Rotation mints `k2`, `k3`, ...; verification
looks up by the token's `kid` header so previously issued tokens remain valid until they age out of the window —
the same pattern as JWKS-based rotation in production IdPs, minus the network.

```bash
pip install -r requirements.txt
uvicorn auth_gateway.app:app --reload

curl -X POST localhost:8000/token -d '{"username": "alice", "password": "wonderland"}' -H "Content-Type: application/json"
curl localhost:8000/me -H "Authorization: Bearer <access_token>"
```

## Tests

```bash
pytest -q   # 48 tests: jwt roundtrip/tamper/expiry/kid, rotation windows, reuse detection,
            # cross-tenant 403s, headers, lockout/throttle, introspection/revocation/watermark,
            # RFC 6238 TOTP vectors, recovery codes, audit events
```

MIT
