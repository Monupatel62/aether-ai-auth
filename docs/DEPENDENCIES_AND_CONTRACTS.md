# Dependencies and Contracts — aether-ai-auth

**Status:** Proposed; identity provider and token profile are not selected.

## Direct dependencies

- Selected identity-provider adapter (TBD).
- Narrow principal/session contract and low-level cryptographic utilities.
- `aether-ai-security` principal/policy primitives where needed.

API and domain services are consumers of Auth's public principal/session contracts. Auth MUST NOT import or depend on API or higher-level domain consumers. This keeps identity/session lifecycle low-level and prevents reverse dependencies or package cycles.

## Owned contracts

Authenticated principal identity, session lifecycle, authentication errors and provider identity mapping. Tenant/workspace membership and role-grant ownership remain unresolved under ADR-0021; Auth must not create a parallel membership/ACL source of truth unless an accepted ADR assigns that responsibility here.

## Required rules

- Define issuer, audience, accepted algorithms, key rotation, expiry and required claims through an approved profile.
- Authentication alone never grants access to a resource.
- Caller-supplied tenant membership or role claims are not authoritative.
- Version principal/session context and stable error categories.
- Define CSRF, logout, revocation, account linking and recovery semantics before implementation.
- Keep tokens, cookies and secrets out of logs.

[Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
