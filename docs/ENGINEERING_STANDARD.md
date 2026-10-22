# Engineering Standard — aether-ai-auth

- Authentication establishes identity; resource owners make authorization decisions.
- Validate tokens against an approved issuer/audience/algorithm/expiry profile.
- Do not trust caller-supplied roles, tenant membership or approval claims.
- Keep principal context minimal and versioned.
- Define secure session, CSRF, logout, revocation and recovery behavior.
- Never log tokens, cookies, authorization headers or recovery secrets.
- Pin and review identity dependencies; document key rotation and incident response.
- Test invalid credentials, privilege-claim spoofing and session lifecycle failures.
