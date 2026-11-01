# Private statement pages (draft)

This branch contains generic shells, a Cloudflare Worker, and local tools. It contains no passcode, passcode verifier, statement text, or encryption key. Only /s1 through /s5 are intended to be gated; the public homepage and other existing routes are unchanged.

## Security design

- The shared code is checked with PBKDF2-HMAC-SHA-256 (600,000 iterations) and a random 16-byte salt. Only the salt and derived verifier are Worker secrets. The plaintext code is never saved in the repository or statement database.
- A Cloudflare Durable Object counts failures atomically by an HMAC-pseudonym of the visitor IP. The fifth incorrect attempt redirects to the homepage and locks that client IP for 24 hours. People behind the same public IP may share a lockout.
- Successful entry issues a signed Secure, HttpOnly, SameSite=Strict cookie that works across all five pages. It is persistent until cleared or revoked by rotating the signing key. Browsers can limit or clear persistent cookies, so no site can guarantee truly indefinite persistence.
- Each successful entry creates a private KV log record with a UTC timestamp and random event ID. No IP address or code is logged.
- Statements are encrypted before upload to private KV using AES-256-CBC with encrypt-then-HMAC-SHA-256. The Worker checks the MAC, then decrypts after a valid cookie. Responses use private/no-store and no-index headers.

A code gate controls access but does not identify who entered it. Anyone who receives the shared code can unlock the pages. The homepage remains public; the Worker routes only /s1 through /s5.

## Cloudflare setup required before deployment

Nothing in Cloudflare has been changed yet. Existing Workers are untouched. Before deployment:

1. Create private KV namespaces for statement ciphertext and successful-entry logs; bind them as STATEMENTS and LOGIN_LOG and replace the placeholder IDs in wrangler.toml.
2. On your own computer, run scripts/create-passcode-verifier.mjs in an interactive terminal and enter the code there; the script hides typing and prints only a random salt plus the PBKDF2 verifier. Enter those two outputs yourself as Worker secrets GATE_SALT_B64 and GATE_HASH_B64. Do not send the code or outputs in chat.
3. Generate random values for SESSION_SIGNING_KEY_B64 (32 bytes) and CONTENT_KEY_B64 (64 bytes); save each directly as a Worker secret. Never place them in public source.
4. Deploy a new Worker from this draft branch only, with workers.dev and preview URLs disabled. This branch's routes affect the five statement paths only.
5. Prepare and review the final five statements in a private JSON file outside GitHub. Seal them locally and upload only the ciphertext to STATEMENTS.
6. Verify unauthenticated, correct-code, wrong-code, lockout, cookie, cache-header, and content-decryption behavior before sharing any hash clues.

Cloudflare routes, KV namespaces, secrets, and deployments have not been changed. The user must enter authentication secrets themselves; the site is not ready for visitors until those steps and checks are complete.

## Seal the private statement text

Create a local JSON object containing exactly s1, s2, s3, s4, and s5, and keep it outside the repository. Set CONTENT_KEY_B64 locally to a random 64-byte base64 key, then run:

    node scripts/seal-statements.mjs < /secure/path/statements.json > /secure/path/statements.sealed.json

Upload only the resulting encrypted values to the private STATEMENTS KV namespace. Never upload the source JSON or key to GitHub.

The first user-supplied paragraph was lightly reframed as a first-person belief and safety concern in the earlier draft plan. Other text should be reviewed by the user before sealing. This does not verify the allegations or guarantee protection from legal claims.
