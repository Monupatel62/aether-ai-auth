# Dependencies and Contracts — aether-ai-auth

**Status:** Proposed; identity provider and token profile are not selected.

## Dependencies

Selected identity provider adapter (TBD) and the narrow aether-ai-security principal/policy contract as needed. API and domain services consume Auth's public principal/session contracts; Auth must not depend on or import those consumers.

## Owned contracts

Authenticated principal identity, session lifecycle, authentication errors and provider identity mapping.

## Required rules

- Define issuer, audience, accepted algorithms, key rotation, expiry and required claims through an approved profile.
- Authentication alone never grants access to a resource.
- Caller-supplied tenant membership or role claims are not authoritative.
- Version principal/session context and stable error categories.
- Define CSRF, logout, revocation, account linking and recovery semantics before implementation.
- Keep tokens, cookies and secrets out of logs.

[Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
