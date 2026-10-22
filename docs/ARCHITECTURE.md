# Architecture — aether-ai-auth

**Status:** Proposed; not implemented.

## Mission
Identity provider integration, session/token validation, user identity mapping and principal lifecycle.

## Ownership
Auth validates identity and session, maps external identities to canonical Aether principals, and defines session lifecycle. It does not own API/domain resource authorization. Canonical tenant-membership and role-grant ownership remains an explicit decision under ADR-0021.

## Authentication flow
1. Validate provider tokens against an approved issuer, audience, signature, expiry and claims profile.
2. Map the external subject to a stable internal principal.
3. Apply session lifecycle and CSRF requirements appropriate to the chosen flow.
4. Pass minimal principal context to consumers over authenticated boundaries.
5. Let each API/domain boundary resolve current membership and authorize every resource/action.

## Open decisions
Identity provider, supported flows, session storage, token profile, account linking and membership ownership require reviewed ADRs. No production identity configuration is claimed.

[Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
