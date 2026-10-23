# aether-ai-auth

**Status:** Authentication boundary core implemented on a feature branch. No identity provider or production token verifier has been selected.

## Implemented

- [Authentication source](src/index.js): Bearer credential parsing, trusted verifier adapter, issuer/audience/expiry/not-before checks, and principal resolution through an injected authoritative membership adapter.
- [Unit tests](test/auth.test.js): malformed/oversized credentials, invalid claims, verifier failures, tenant selection, and membership resolution failure.
- Dependency-free Node.js package with Node 20/22 CI.

## Security boundary

- The injected `verifyAccessToken` must perform real cryptographic verification, restrict algorithms, validate signature/key rotation, and bind issuer/audience. This package does not verify JWT signatures itself.
- The `x-tenant-id` header is only an untrusted selector. `resolvePrincipal` must check membership against authoritative state and return the canonical tenant.
- The implementation deliberately does not trust a tenant claim from the token as the membership source of truth.
- No identity-provider adapter, revocation/session store, refresh flow, workload identity, MFA, or production key rotation is included yet.

## Documentation

- [Repository specification](docs/REPOSITORY_SPECIFICATION.md)
- [Project specification](docs/PROJECT_SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Dependencies and contracts](docs/DEPENDENCIES_AND_CONTRACTS.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security review](docs/SECURITY_REVIEW.md)
- [Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
