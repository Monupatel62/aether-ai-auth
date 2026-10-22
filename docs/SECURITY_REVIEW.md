# Security Review — aether-ai-auth

**Status:** Design checklist only; no security audit or certification is claimed.

## Main risks
Token confusion, issuer/audience mismatch, session fixation, CSRF, stolen refresh tokens, account-linking takeover, untrusted role claims and stale sessions after revocation.

## Required controls
- Validate issuer, audience, signature, expiry and claims against an approved profile.
- Use secure session/cookie practices and CSRF defenses where applicable.
- Rotate/revoke credentials and define logout/recovery behavior.
- Never treat authentication as resource authorization.
- Do not create a parallel tenant membership or role-grant store without ADR approval.
- Redact tokens, cookies, authorization headers and recovery secrets from telemetry.

## Verification plan
- [ ] Invalid signature, issuer, audience and expiry cases.
- [ ] CSRF/session fixation/logout/revocation cases as applicable.
- [ ] Untrusted role/tenant claim rejection.
- [ ] Account-linking and recovery abuse cases.
