/**
 * Authentication boundary adapters.
 *
 * verifyAccessToken MUST perform cryptographic verification (signature/key
 * rotation/algorithm restrictions) using a trusted issuer configuration.
 * resolvePrincipal MUST resolve the subject and optional tenant selector against
 * authoritative membership state. This package intentionally selects no IdP.
 */
export class AuthenticationError extends Error {
  constructor(code, message = "Authentication failed") { super(message); this.name = "AuthenticationError"; this.code = code; }
}

const TOKEN_MAX_LENGTH = 16_384;
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function validString(value) { return typeof value === "string" && value.length > 0 && value.trim() === value; }

export function createAuthenticator({ verifyAccessToken, resolvePrincipal, issuer, audience, clock = () => Math.floor(Date.now() / 1000) }) {
  if (typeof verifyAccessToken !== "function") throw new TypeError("verifyAccessToken adapter is required");
  if (typeof resolvePrincipal !== "function") throw new TypeError("resolvePrincipal adapter is required");
  if (!validString(issuer) || !validString(audience)) throw new TypeError("Explicit issuer and audience are required");
  if (typeof clock !== "function") throw new TypeError("clock must be a function");

  return Object.freeze({
    async authenticate({ headers } = {}) {
      const authorization = headers?.authorization;
      if (typeof authorization !== "string" || authorization.length > TOKEN_MAX_LENGTH + 32) {
        throw new AuthenticationError("missing_credentials");
      }
      const match = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(authorization);
      if (!match || match[1].length > TOKEN_MAX_LENGTH) throw new AuthenticationError("invalid_credentials");

      let claims;
      try { claims = await verifyAccessToken(match[1], { issuer, audience }); }
      catch { throw new AuthenticationError("invalid_credentials"); }
      if (!isRecord(claims) || !validString(claims.sub) || claims.iss !== issuer) {
        throw new AuthenticationError("invalid_claims");
      }
      const tokenAudiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!tokenAudiences.includes(audience)) throw new AuthenticationError("invalid_audience");
      const now = clock();
      if (!Number.isSafeInteger(claims.exp) || claims.exp <= now) throw new AuthenticationError("expired_token");
      if (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now)) {
        throw new AuthenticationError("token_not_yet_valid");
      }

      // This header is only an untrusted selector. The resolver must verify that
      // the subject is a member of the selected tenant before returning a principal.
      const tenantSelector = headers["x-tenant-id"];
      if (tenantSelector !== undefined && (typeof tenantSelector !== "string" || tenantSelector.length > 256)) {
        throw new AuthenticationError("invalid_tenant_selector");
      }
      let principal;
      try {
        principal = await resolvePrincipal({ subject: claims.sub, tenantSelector, claims });
      } catch {
        throw new AuthenticationError("principal_resolution_failed");
      }
      if (!isRecord(principal) || !validString(principal.id) || !validString(principal.tenantId)) {
        throw new AuthenticationError("principal_resolution_failed");
      }
      return Object.freeze({ id: principal.id, tenantId: principal.tenantId });
    },
  });
}
