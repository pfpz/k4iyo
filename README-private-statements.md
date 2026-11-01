# Private statement pages (draft)

This branch contains generic page shells, a Cloudflare Worker, and local helper scripts. It contains no passcode, passcode verifier, statement text, or encryption key. Only /s1 through /s5 are intended to be gated; the public homepage and other existing routes are unchanged.

## Current Cloudflare state

- Private KV namespace `k4iyo-private-statements` is created and intended for encrypted statement records.
- Private KV namespace `k4iyo-private-login-log` is created and intended for successful-entry timestamps.
- Worker `k4iyo-private-statements` exists, but its public workers.dev URL is disabled.
- Production bindings STATEMENTS and LOGIN_LOG point to the two private namespaces. The draft Worker code and `GateLimiter` Durable Object class have been deployed with KV and Durable Object bindings. Its workers.dev and preview URLs are disabled, and it has no custom-domain routes, so it is not publicly serving these pages.
- Existing Workers, the homepage, and the main GitHub branch have not been changed.

## Security design in the draft Worker

- The shared access code is checked with PBKDF2-HMAC-SHA-256 (600,000 iterations) and a random 16-byte salt. Only the salt and derived verifier are Worker secrets. The plaintext code is never saved in the repository or statement database.
- A Cloudflare Durable Object counts failures atomically by an HMAC-pseudonym of the visitor IP. The fifth incorrect attempt redirects to the homepage and locks that client IP for 24 hours. People behind the same public IP may share a lockout.
- Successful entry issues a signed Secure, HttpOnly, SameSite=Strict cookie shared by all five pages. It is persistent until cleared or revoked by rotating the signing key. Browsers can limit or clear persistent cookies, so no site can guarantee truly indefinite persistence.
- Each successful entry creates a private KV log record with a UTC timestamp and random event ID. No IP address or code is logged.
- Statements are encrypted before upload to private KV using AES-256-CBC with encrypt-then-HMAC-SHA-256. The Worker verifies the MAC before decrypting after a valid cookie. Responses use private/no-store and no-index headers.
- A shared code controls access but does not identify who entered it. Anyone who receives the code can unlock the pages.

## Setup still required before the statement routes can be enabled

1. Keep the `GateLimiter` Durable Object migration and `STATEMENTS` and `LOGIN_LOG` KV bindings in sync with `wrangler.toml`.
2. On your own computer, run `scripts/create-passcode-verifier.mjs` in an interactive terminal and enter the access code there; the script hides typing and prints only a random salt plus the PBKDF2 verifier. Enter those outputs yourself as Worker secrets `GATE_SALT_B64` and `GATE_HASH_B64`. Do not send the code or outputs in chat.
3. Run `node scripts/create-random-worker-secrets.mjs` locally to generate random values for `SESSION_SIGNING_KEY_B64` (32 bytes) and `CONTENT_KEY_B64` (64 bytes). Add them as Worker secrets yourself; do not commit or share the output. Keep the content key available locally only while sealing the statements.
4. Verify that the Worker fails closed before attaching custom-domain routes for only `k4iyo.com/s1*` through `k4iyo.com/s5*`. Keep workers.dev and preview URLs disabled.
5. Prepare and review the final five statements in a private JSON file outside GitHub. Seal them locally and upload only the ciphertext to the private `STATEMENTS` KV namespace.
6. Verify unauthenticated, correct-code, wrong-code, lockout, cookie, cache-header, and content-decryption behavior before sharing any hash clues. Keep routes unattached until secrets and encrypted statement records are in place.

No statement text, access code, verifier, or encryption key has been uploaded to Cloudflare. The homepage remains public.

## Seal private statement text

Create a local JSON object containing exactly `s1`, `s2`, `s3`, `s4`, and `s5`, and keep it outside the repository. Set `CONTENT_KEY_B64` locally to a random 64-byte base64 key, then run:

    node scripts/seal-statements.mjs < /secure/path/statements.json > /secure/path/statements.sealed.json

Upload only the resulting encrypted values to the private `STATEMENTS` KV namespace. Never upload the source JSON or key to GitHub.

The first user-supplied paragraph was lightly reframed as a first-person belief and safety concern in the earlier draft plan. Other text should be reviewed by the user before sealing. This does not verify the allegations or guarantee protection from legal claims.
