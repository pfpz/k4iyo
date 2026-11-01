#!/usr/bin/env node
import { createCipheriv, createHmac, randomBytes } from "node:crypto";

const keyText = process.env.CONTENT_KEY_B64;
if (!keyText) {
  console.error("Set CONTENT_KEY_B64 in your shell to a private 64-byte base64 key.");
  process.exit(2);
}
const key = Buffer.from(keyText, "base64");
if (key.length !== 64) {
  console.error("CONTENT_KEY_B64 must decode to exactly 64 bytes.");
  process.exit(2);
}
let input = "";
for await (const chunk of process.stdin) input += chunk;
const statements = JSON.parse(input);
const ids = Object.keys(statements).sort();
if (ids.length !== 5 || ids.some((id, index) => id !== "s" + (index + 1))) {
  console.error("Input must be a JSON object containing exactly s1, s2, s3, s4, and s5.");
  process.exit(2);
}
const output = ids.map(id => {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([cipher.update(String(statements[id]), "utf8"), cipher.final()]);
  const mac = createHmac("sha256", key.subarray(32))
    .update(Buffer.concat([Buffer.from(id + "\0", "utf8"), iv, ciphertext]))
    .digest();
  return { key: id, value: JSON.stringify({
    iv: iv.toString("base64"), ciphertext: ciphertext.toString("base64"), mac: mac.toString("base64")
  }) };
});
process.stdout.write(JSON.stringify(output, null, 2) + "\n");
