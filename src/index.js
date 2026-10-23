export const AUTH_CONTRACT_VERSION = "1.0";
export const MAX_SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 7;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$/;

function identifier(value, field) {
  if (typeof value !== "string" || !ID_RE.test(value)) throw new TypeError(`${field} must be a valid identifier`);
  return value;
}
function timestamp(value, field) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new TypeError(`${field} must be a valid timestamp`);
  return new Date(value).toISOString();
}

/** Canonical principal identity; deliberately contains no tenant-membership or role-grant claims. */
export function createPrincipal(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("principal input must be an object");
  const status = input.status ?? "active";
  if (!["active", "disabled", "deleted"].includes(status)) throw new TypeError("invalid principal status");
  return Object.freeze({
    contractVersion: AUTH_CONTRACT_VERSION,
    principalId: identifier(input.principalId, "principalId"),
    identityProvider: identifier(input.identityProvider, "identityProvider"),
    providerSubject: identifier(input.providerSubject, "providerSubject"),
    status,
    ...(typeof input.displayName === "string" && input.displayName.trim() ? { displayName: input.displayName.trim().slice(0, 120) } : {}),
    ...(typeof input.emailVerified === "boolean" ? { emailVerified: input.emailVerified } : {}),
    createdAt: timestamp(input.createdAt, "createdAt"),
  });
}

/** Validates session envelope semantics only; it does NOT verify a JWT/signature or authenticate a caller. */
export function validateSessionEnvelope(input = {}, { now = Date.now(), maxLifetimeSeconds = MAX_SESSION_LIFETIME_SECONDS } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("session input must be an object");
  const issuedAt = Date.parse(input.issuedAt);
  const expiresAt = Date.parse(input.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) throw new TypeError("issuedAt and expiresAt must be valid timestamps");
  if (expiresAt <= issuedAt) throw new RangeError("expiresAt must be after issuedAt");
  if (issuedAt > now + 60_000) throw new RangeError("session issuedAt is in the future");
  if (expiresAt <= now) throw new RangeError("session has expired");
  if ((expiresAt - issuedAt) / 1000 > maxLifetimeSeconds) throw new RangeError("session lifetime exceeds configured maximum");
  return Object.freeze({
    contractVersion: AUTH_CONTRACT_VERSION,
    sessionId: identifier(input.sessionId, "sessionId"),
    principalId: identifier(input.principalId, "principalId"),
    issuer: identifier(input.issuer, "issuer"),
    audience: identifier(input.audience, "audience"),
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    ...(typeof input.correlationId === "string" && ID_RE.test(input.correlationId) ? { correlationId: input.correlationId } : {}),
  });
}

export function createSessionRevocationEvent(input = {}) {
  return Object.freeze({
    contractVersion: AUTH_CONTRACT_VERSION,
    eventType: "auth.session.revocation-requested",
    eventId: identifier(input.eventId, "eventId"),
    sessionId: identifier(input.sessionId, "sessionId"),
    principalId: identifier(input.principalId, "principalId"),
    reasonCode: identifier(input.reasonCode, "reasonCode"),
    occurredAt: timestamp(input.occurredAt, "occurredAt"),
    ...(typeof input.correlationId === "string" && ID_RE.test(input.correlationId) ? { correlationId: input.correlationId } : {}),
  });
}

/** Browser cookie policy defaults for a session cookie; actual HTTP setting is the caller's responsibility. */
export function getSessionCookiePolicy({ secure = true, sameSite = "Lax", path = "/" } = {}) {
  if (secure !== true) throw new TypeError("session cookies must be Secure");
  if (!["Strict", "Lax"].includes(sameSite)) throw new TypeError("sameSite must be Strict or Lax");
  if (path !== "/") throw new TypeError("session cookie path must be /");
  return Object.freeze({ httpOnly: true, secure: true, sameSite, path });
}
