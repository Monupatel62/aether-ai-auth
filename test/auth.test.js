import test from "node:test";
import assert from "node:assert/strict";
import { AuthenticationError, createAuthenticator } from "../src/index.js";

const issuer = "https://identity.example.test";
const audience = "aether-api";
const claims = { sub: "external-user-1", iss: issuer, aud: audience, exp: 2000 };
function setup(overrides = {}) {
  const calls = [];
  const auth = createAuthenticator({
    issuer, audience, clock: () => 1000,
    verifyAccessToken: async (token, options) => { calls.push({ token, options }); return claims; },
    resolvePrincipal: async (input) => ({ id: input.subject, tenantId: input.tenantSelector ?? "tenant-default" }),
    ...overrides,
  });
  return { auth, calls };
}

test("validates token through verifier and resolves principal through membership adapter", async () => {
  const { auth, calls } = setup();
  const principal = await auth.authenticate({ headers: { authorization: "Bearer abc.def.ghi", "x-tenant-id": "tenant-a" } });
  assert.deepEqual(principal, { id: "external-user-1", tenantId: "tenant-a" });
  assert.equal(calls[0].options.issuer, issuer);
});

test("rejects missing, malformed, and oversized bearer credentials", async () => {
  const { auth } = setup();
  await assert.rejects(auth.authenticate({ headers: {} }), AuthenticationError);
  await assert.rejects(auth.authenticate({ headers: { authorization: "Basic abc" } }), AuthenticationError);
  await assert.rejects(auth.authenticate({ headers: { authorization: "Bearer " + "a".repeat(17000) } }), AuthenticationError);
});

test("rejects invalid issuer, audience, expiry, and not-before claims", async () => {
  for (const bad of [
    { ...claims, iss: "https://attacker.invalid" },
    { ...claims, aud: "other-api" },
    { ...claims, exp: 1000 },
    { ...claims, nbf: 1001 },
  ]) {
    const { auth } = setup({ verifyAccessToken: async () => bad });
    await assert.rejects(auth.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } }), AuthenticationError);
  }
});

test("fails closed when verifier or tenant membership resolver fails", async () => {
  const verifierDown = setup({ verifyAccessToken: async () => { throw new Error("secret token"); } }).auth;
  await assert.rejects(verifierDown.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } }), (e) => e.code === "invalid_credentials" && !e.message.includes("secret"));
  const membershipDown = setup({ resolvePrincipal: async () => { throw new Error("private db error"); } }).auth;
  await assert.rejects(membershipDown.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } }), (e) => e.code === "principal_resolution_failed");
});

test("does not trust token claims as the canonical tenant", async () => {
  let selected;
  const { auth } = setup({ verifyAccessToken: async () => ({ ...claims, tenantId: "forged-tenant" }), resolvePrincipal: async (input) => { selected = input.tenantSelector; return { id: input.subject, tenantId: "verified-tenant" }; } });
  const principal = await auth.authenticate({ headers: { authorization: "Bearer abc.def.ghi", "x-tenant-id": "untrusted-selector" } });
  assert.equal(selected, "untrusted-selector");
  assert.equal(principal.tenantId, "verified-tenant");
});


test("bounds token verification and tenant principal resolution", async () => {
  const verifier = setup({ timeoutMs: 5, verifyAccessToken: () => new Promise(() => {}) }).auth;
  await assert.rejects(verifier.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } }), (e) => e.code === "verification_timeout");
  const resolver = setup({ timeoutMs: 5, resolvePrincipal: () => new Promise(() => {}) }).auth;
  await assert.rejects(resolver.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } }), (e) => e.code === "principal_resolution_timeout");
});

test("passes abort signals to auth adapters", async () => {
  let verifySignal;
  const { auth } = setup({ verifyAccessToken: async (_token, options) => { verifySignal = options.signal; return claims; } });
  await auth.authenticate({ headers: { authorization: "Bearer abc.def.ghi" } });
  assert.ok(verifySignal instanceof AbortSignal);
  assert.equal(verifySignal.aborted, false);
});
