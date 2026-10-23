# Session and Token Revocation Contract

**Status:** Proposed contract for review; no runtime revocation implementation is claimed.
**Owners:** Auth owns session lifecycle and revocation events; Gateway enforces the accepted validation policy. Cache is a supporting mechanism, not the authority for identity or membership.
**Open decision:** Identity provider, token profile, revocation store/backend, and consistency target require ADR review. This document does not decide ADR-0021.

## 1. Security goals

- Logout, administrative session revoke, credential-compromise response, or account disable must invalidate the affected session according to the accepted policy.
- JWT signature and expiry validation alone must not be treated as sufficient for immediate session revocation where the product promises revocation-aware sessions.
- Revocation checks and cache failures must fail closed for protected operations; cache outage must never convert a revoked or unverifiable session into an accepted session.
- Session revocation and workspace membership/role revocation are distinct. Membership authority remains unresolved under ADR-0021; token claims must not become canonical membership authority.
- No access token, refresh token, raw session identifier, or secret is written to default logs or telemetry.

## 2. Contract entities

A revocation record/event should carry the minimum data needed to correlate and enforce revocation:
- `event_id`: globally unique event identifier for deduplication.
- `event_type`: `session.revoked`, `session.revocation_cleared` (only if the selected model permits restoration), or `principal.disabled`.
- `principal_id`: stable internal principal identifier.
- `session_id` or a keyed digest of the session identifier; never publish raw bearer tokens.
- `issued_at`: UTC timestamp.
- `effective_at`: UTC timestamp from which the revocation applies.
- `reason_code`: bounded enum, never free-form sensitive notes.
- `schema_version`: explicit version.
- `correlation_id`: trace correlation value, not an authorization credential.

Exact schema, producer identity, signing/authentication, delivery transport, retention, and restoration semantics must be finalized before implementation. Events are untrusted until producer authentication and schema validation succeed.

## 3. Enforcement flow

1. Gateway validates token cryptography, issuer, audience, expiry, permitted algorithms, and required claims according to the accepted token profile.
2. Gateway obtains a trusted session identifier or equivalent revocation handle from validated token/session context.
3. Gateway checks the revocation decision using the accepted authoritative mechanism and bounded cache policy.
4. A confirmed revoked session is rejected with `401 Unauthorized`; response does not disclose session details.
5. An unknown or unavailable revocation result follows the approved fail-closed policy for protected endpoints; it must not silently fall back to signature-only acceptance if immediate revocation is required.
6. Auth emits the revocation event durably and retries delivery with deduplication. Gateway/cache consumers process events idempotently and reject stale/out-of-order events according to version or effective-time rules.
7. Revocation state must be checked again for queued work and at execution-time authorization boundaries, not only when a job is enqueued.
8. Reauthentication creates a new session identity; a revoked session is not reactivated by refreshing the same credentials unless a separately approved recovery flow explicitly permits it.

## 4. Cache and consistency requirements

- Cache keys must be namespaced and must not permit cross-tenant or cross-session collisions.
- Cache values must have a bounded TTL and explicit schema/version.
- Revocation writes must be durable in the selected authority before a success response claims the session was revoked.
- Invalidation events must be idempotent; duplicate events cannot restore access.
- Out-of-order delivery must not allow an older active/stale cache value to override a newer revocation.
- Cache misses must consult the selected authority; a cache miss is not proof that a session is active.
- Cache outage behavior, fallback authority, maximum stale interval, and regional replication guarantees require an explicit ADR.
- Never store raw bearer tokens as cache keys. Use a safe session identifier or keyed digest with key-rotation requirements documented.

## 5. Proposed measurable acceptance tests

These are proposed criteria, not executed tests. The product owner/security reviewer must approve the service-level target before it becomes a release gate.

| ID | Scenario | Expected result |
|---|---|---|
| REV-001 | Revoke a session, then send a request using that session | Gateway returns 401 after revocation is effective |
| REV-002 | Present an expired token | 401; no downstream protected operation runs |
| REV-003 | Present invalid signature, issuer, audience, or algorithm | 401; fail closed |
| REV-004 | Revoke session while a cached active entry exists | Invalidation or authoritative check prevents continued acceptance within the approved consistency bound |
| REV-005 | Cache/revocation authority unavailable | Protected request fails closed; no signature-only fallback |
| REV-006 | Deliver the same revocation event twice | Same final revoked state; no duplicate side effects |
| REV-007 | Deliver stale event after newer revocation | Older event cannot reactivate the session |
| REV-008 | Queue work, revoke session, then execute work | Worker rechecks current authority and denies protected side effects |
| REV-009 | Revoke one session for a principal with multiple sessions | Only intended session(s) are revoked according to approved scope |
| REV-010 | Membership is revoked but token remains cryptographically valid | Resource authorization rejects according to canonical membership contract; ADR-0021 remains a prerequisite |
| REV-011 | Cache key collision attempts across principals/tenants | No revocation state is shared incorrectly |
| REV-012 | Logs capture revocation path | No raw bearer/refresh token or secret appears |
| REV-013 | Revocation event has invalid schema or unauthenticated producer | Consumer rejects and alerts; no authorization state is weakened |
| REV-014 | Reauthenticate after revocation | New session may be used only after normal authentication; old session remains revoked |

## 6. Proposed latency objective

A 500 ms revocation objective has been discussed as a candidate, not an approved guarantee. Before adopting it, define:
- measurement start: Auth's durable revocation acknowledgment or initiating logout request;
- measurement end: time after which every protected Gateway instance and queued-work consumer rejects the old session;
- percentile and observation window (for example, p99 over a defined load test);
- behavior during regional partition, event backlog, cache outage, and authority outage;
- whether the guarantee is strict immediate revocation or a bounded propagation SLO.

Do not claim “revoked within 500 ms” until the owner approves the objective and a repeatable distributed test demonstrates it under load and failure conditions.

## 7. Rollout and operations

Before production:
- Approve token/session profile and revocation authority.
- Document event authentication, idempotency, ordering/version strategy, retention, and replay protection.
- Add dashboards for propagation lag, revocation lookup failures, stale-cache decisions, queue reauthorization denials, and fail-closed responses.
- Define alert thresholds, emergency kill switch, recovery/reconciliation process, and incident runbook.
- Run negative tests against multiple Gateway instances and queue workers, including delay, duplicate, reordering, and outage injection.
- Document privacy/retention for identifiers and security audit events.

## 8. Decision boundaries

This contract does not choose an identity provider, cache backend, canonical tenant membership owner, or final latency SLO. Canonical tenant-membership/role-grant ownership remains ADR-0021 and must be decided by the product owner. Authentication, session revocation, and membership authorization remain separate concepts.
