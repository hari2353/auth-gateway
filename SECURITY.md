# Security Notes

This service **is** the authentication boundary for the demo suite, so its controls are the point.

## Controls in place

- **Password hashing**: PBKDF2-HMAC-SHA256, 100k iterations, per-user random salt, constant-time
  comparison via `secrets.compare_digest`
- **JWT hardening**: algorithm pinned to HS256 (`alg=none` / confusion attacks rejected), tokens carry
  `kid` headers resolved through a versioned KeyStore — unknown-kid tokens fail closed, signatures compared
  with `hmac.compare_digest`, expiry enforced server-side
- **Key rotation**: bounded version window; rotation never invalidates in-flight tokens abruptly, purged
  kids stop verifying immediately after retention — zero-downtime rotation semantics
- **Refresh-token reuse detection**: refresh JTIs are single-use; replaying a consumed refresh token
  returns 401 (revocation-list pattern)
- **Object-level authorization**: `/v1/tenants/{tenant_id}/profile` enforces token-tenant == path-tenant
  (403 otherwise) — the cross-tenant IDOR class is covered by tests
- **Token-type separation**: refresh tokens are rejected on access-token endpoints and vice versa
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`
  (tokens must not be cached)
- **Credential hygiene**: demo users live in an in-memory store with throwaway passwords; no credentials
  in source control, no secrets in logs

## Known gaps (deliberate for demo scope)

- In-memory user store and revocation list — swap for a DB + Redis in production
- HS256 symmetric keys — production IdPs should use RS256/ES256 with JWKS distribution
- No rate limiting / lockout on `/token` — front with a proxy or add throttling middleware
