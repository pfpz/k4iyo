# Private statement pages (draft)

This branch contains only generic HTML shells and the server-side Worker. It does not include statement text or encryption keys. The public GitHub Pages origin therefore cannot expose the statements.

## Request flow

1. Cloudflare Access authenticates visitors against an explicit email allow-list.
2. The Worker validates the Access JWT signature, issuer, audience, and expiry.
3. The Worker loads a statement ciphertext from a private Cloudflare KV namespace.
4. The Worker verifies HMAC before AES-256-CBC decryption, then returns HTML with private/no-store and no-index headers.
5. The key is configured only as a Cloudflare Worker secret; it is never committed.

SHA-256 digests of the canonical /s1 through /s5 URLs can be used as puzzle clues after deployment. A digest is not access control. The actual paths remain protected by Cloudflare Access and the Worker.

## Current status

No Cloudflare resources, Access applications, routes, KV namespaces, secrets, or DNS settings have been changed. Cloudflare currently has no Pages project for this site and Zero Trust Access is not initialized. Existing Workers were left untouched. This source branch is not the production branch.

## Required setup before deployment

- Initialize Cloudflare Zero Trust and create an Access self-hosted application covering k4iyo.com/s1* through k4iyo.com/s5*.
- Use email one-time PIN and allow only addresses the site owner explicitly approves. Do not use a public or everyone policy.
- Set ACCESS_TEAM_DOMAIN to the Cloudflare Access team hostname and ACCESS_AUD to the application's audience tag.
- Create a private Workers KV namespace and bind it as STATEMENTS; replace the placeholder namespace ID in wrangler.toml.
- Generate a random 64-byte key and configure its base64 value as the Worker secret STATEMENT_KEY_B64. Do not commit or paste the key into public source.
- Keep workers_dev and preview URLs disabled. Deploy only after Access policy, Worker secret, and KV bindings are configured. Verify unauthorized requests are blocked and authorized pages return private/no-store headers.

## Seal data locally

Prepare a private JSON file with the five user-reviewed statements keyed as s1 through s5. Keep that file outside the repository. Generate a key with openssl rand -base64 64, store it in a shell environment variable named STATEMENT_KEY_B64, then run:

    node scripts/seal-statements.mjs < /secure/path/statements.json > /secure/path/statements.sealed.json

Upload only the resulting encrypted JSON values to the private KV namespace. Never upload the source JSON or key to GitHub. Deployment is not ready until Access policy, Worker secrets, and KV bindings have been configured and tested.

## Editorial note

The first statement in the user's supplied text was lightly reframed as a first-person belief and safety concern. The remaining statements should be reviewed by the user before they are sealed; this draft does not verify the allegations or guarantee protection from legal claims. For legal proceedings or immediate safety concerns, use qualified counsel and appropriate authorities.
