# Private statement pages (draft)

This branch contains generic page shells, a Cloudflare Worker, and local helper scripts. It contains no passcode, passcode verifier, statement text, or encryption key. Only /s1 through /s5 are intended to be gated; the public homepage and other existing routes are unchanged.

## Current Cloudflare state

- Private KV namespace `k4iyo-private-statements` is created and intended for encrypted statement records.
- Private KV namespace `k4iyo-private-login-log` is created and intended for successful-entry timestamps.
- Worker `k4iyo-private-statements` is deployed; its workers.dev and preview URLs are disabled.
- Production bindings `STATEMENTS`, `LOGIN_LOG`, and `GATE_LIMITER` are connected. The four required Worker secrets are configured, and the `STATEMENTS` namespace contains the five encrypted records (`s1`–`s5`). No custom-domain routes are attached yet, so the pages are not publicly serving.
- Existing Workers, the homepage, and the main GitHub branch have not been changed.

## Security design in the draft Worker

- The shared access code is checked with PBKDF2-HMAC-SHA-256 (600,000 iterations) and a random 16-byte salt. Only the salt and derived verifier are Worker secrets. The plaintext code is never saved in the repository or statement database.
- A Cloudflare Durable Object counts failures atomically by an HMAC-pseudonym of the visitor IP. The fifth incorrect attempt redirects to the homepage and locks that client IP for 24 hours. People behind the same public IP may share a lockout.
- Successful entry issues a signed Secure, HttpOnly, SameSite=Strict cookie shared by all five pages. It is persistent until cleared or revoked by rotating the signing key. Browsers can limit or clear persistent cookies, so no site can guarantee truly indefinite persistence.
- Each successful entry creates a private KV log record with a UTC timestamp and random event ID. No IP address or code is logged.
- Statements are encrypted before upload to private KV using AES-256-CBC with encrypt-then-HMAC-SHA-256. The Worker verifies the MAC before decrypting after a valid cookie. Responses use private/no-store and no-index headers.
- A shared code controls access but does not identify who entered it. Anyone who receives the code can unlock the pages.

## Remaining launch steps

1. Attach only the five approved route patterns `k4iyo.com/s1*` through `k4iyo.com/s5*` after final action-time approval.
2. Verify the gate, session cookie, 24-hour lockout, no-store headers, and successful content decryption. Keep workers.dev and preview URLs disabled.

Statement plaintext, access code, verifier, and encryption keys are not stored in GitHub. The homepage remains public.

## Seal private statement text

Create a local JSON object containing exactly `s1`, `s2`, `s3`, `s4`, and `s5`, and keep it outside the repository. Run this in an interactive terminal, then enter the same content key that is stored as the Cloudflare Worker secret when prompted (input is hidden):

    node scripts/seal-private-statements.mjs /secure/path/statements.json /secure/path/statements.sealed.json

Upload only the resulting encrypted values to the private `STATEMENTS` KV namespace. Never upload the source JSON or key to GitHub.

The first user-supplied paragraph was lightly reframed as a first-person belief and safety concern in the earlier draft plan. Other text should be reviewed by the user before sealing. This does not verify the allegations or guarantee protection from legal claims.
