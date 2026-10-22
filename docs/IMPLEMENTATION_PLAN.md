# Implementation Plan — aether-ai-auth

**Status:** Planning only.

1. Decide identity provider and supported sign-in/session flows through ADRs.
2. Resolve canonical tenant membership and role-grant ownership; do not create a parallel ACL store.
3. Define token validation profile, principal mapping and session lifecycle contracts.
4. Threat-model login, callback, logout, refresh, account linking and recovery flows.
5. Implement only after approval with secure session and CSRF behavior appropriate to the selected design.
6. Add invalid signature, issuer/audience mismatch, expiry, CSRF, logout/revocation and privilege-claim tests.
7. Add dependency/license review, secret scanning and operational incident runbooks.

No production authentication claim until negative tests, security review and provider configuration are verified.
