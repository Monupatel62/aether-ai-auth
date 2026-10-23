import test from "node:test";
import assert from "node:assert/strict";
import { createPrincipal, validateSessionEnvelope, createSessionRevocationEvent, getSessionCookiePolicy } from "../src/index.js";

const now = Date.parse("2026-10-23T09:00:00.000Z");
const session = { sessionId: "session-1", principalId: "principal-1", issuer: "aether-auth", audience: "aether-api", issuedAt: "2026-10-23T08:00:00.000Z", expiresAt: "2026-10-23T10:00:00.000Z" };

test("creates canonical principal without membership or role grants", () => {
  const principal = createPrincipal({ principalId: "principal-1", identityProvider: "provider-placeholder", providerSubject: "subject-1", status: "active", createdAt: "2026-01-01T00:00:00Z", tenantId: "tenant-a", roles: ["admin"] });
  assert.equal(principal.principalId, "principal-1");
  assert.equal("tenantId" in principal, false);
  assert.equal("roles" in principal, false);
});

test("validates session time bounds and required issuer/audience", () => {
  assert.equal(validateSessionEnvelope(session, { now }).sessionId, "session-1");
  assert.throws(() => validateSessionEnvelope({ ...session, expiresAt: session.issuedAt }, { now }), /after issuedAt/);
  assert.throws(() => validateSessionEnvelope({ ...session, expiresAt: "2026-10-23T08:30:00Z" }, { now }), /expired/);
  assert.throws(() => validateSessionEnvelope({ ...session, issuedAt: "2026-10-24T00:00:00Z", expiresAt: "2026-10-24T01:00:00Z" }, { now }), /future/);
  assert.throws(() => validateSessionEnvelope({ ...session, expiresAt: "2026-11-01T08:00:00Z" }, { now }), /maximum/);
});

test("creates payload-free session revocation events", () => {
  const event = createSessionRevocationEvent({ eventId: "event-1", sessionId: "session-1", principalId: "principal-1", reasonCode: "logout", occurredAt: "2026-10-23T09:00:00Z", token: "do-not-copy" });
  assert.equal(event.eventType, "auth.session.revocation-requested");
  assert.equal("token" in event, false);
});

test("enforces secure HTTP-only session cookie policy", () => {
  assert.deepEqual(getSessionCookiePolicy(), { httpOnly: true, secure: true, sameSite: "Lax", path: "/" });
  assert.throws(() => getSessionCookiePolicy({ secure: false }), /Secure/);
  assert.throws(() => getSessionCookiePolicy({ sameSite: "None" }), /Strict or Lax/);
});
