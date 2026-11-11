# Class 7 — Fix the Login

I fixed the JWT verification in NotesApp.

I changed `verify_jwt()` to accept only HS256 tokens and always verify the signature. I also replaced the weak JWT secret with a new random secret loaded from an environment variable.

## Audit

| Test | HTTP Status | Result |
|---|---|---|
| Forged token with `alg: none` | 401 Unauthorized | PASS |
| Forged HS256 token signed with `s3cr3t` | 401 Unauthorized | PASS |
| Valid HS256 token signed with the new secret | 200 OK | PASS |

I also checked that Alice could still access her student dashboard.

Both forged tokens were rejected, while valid authentication continued to work.