#!/usr/bin/env node
import { randomBytes } from "node:crypto";

// Run locally and add each value directly as a Worker secret. Do not commit or
// share the output. CONTENT_KEY_B64 is also needed locally to seal statements.
process.stdout.write(JSON.stringify({
  SESSION_SIGNING_KEY_B64: randomBytes(32).toString("base64"),
  CONTENT_KEY_B64: randomBytes(64).toString("base64")
}, null, 2) + "\n");
