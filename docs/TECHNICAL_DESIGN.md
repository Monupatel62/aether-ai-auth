# Technical Design — aether-ai-auth

**Status:** Proposed design, not implementation evidence.

## Purpose
Establish authenticated principals and session lifecycle for Aether AI.

## Boundaries
Auth owns identity proof and session state. The resource-owning API/domain service owns authorization. Canonical tenant membership and role-grant ownership remain unresolved under ADR-0021.

## Proposed flow
Validate provider response/token against an approved profile; map external subject to internal principal; create, refresh or revoke session according to policy; pass minimal principal context; consumers independently resolve current membership and resource authorization. Fail closed on invalid, expired or unverifiable authentication state.

## Security constraints
Never trust client-supplied roles, tenant membership or approvals. Protect cookies/tokens, prevent CSRF where applicable, redact credentials, and define key rotation and incident revocation.

## Open decisions
Provider, token/session profile, account recovery/linking and canonical membership owner require review.
