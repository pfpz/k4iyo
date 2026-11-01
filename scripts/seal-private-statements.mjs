#!/usr/bin/env node
import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  console.error("Usage: node scripts/seal-private-statements.mjs <private-json-file> <sealed-output-file>");
  process.exit(2);
}
if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
  console.error("Run in an interactive terminal so the content key can be entered without echo.");
  process.exit(2);
}

process.stdout.write("Enter CONTENT_KEY_B64 (input hidden): ");
process.stdin.setRawMode(true);
process.stdin.setEncoding("utf8");
process.stdin.resume();
let entered = "";
const keyText = await new Promise((resolve, reject) => {
  process.stdin.on("data", chunk => {
    for (const char of chunk) {
      if (char === "\u0003") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        reject(new Error("Cancelled"));
        return;
      }
      if (char === "\r" || char === "\n") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write("\n");
        resolve(entered);
        return;
      }
      if (char === "\u007f" || char === "\b") entered = entered.slice(0, -1);
      else if (entered.length < 256) entered += char;
    }
  });
});

try {
  const key = Buffer.from(keyText, "base64");
  if (key.length !== 64 || key.toString("base64") !== keyText) throw new Error("Content key must be canonical base64 for exactly 64 random bytes.");
  const statements = JSON.parse(readFileSync(inputPath, "utf8"));
  const ids = Object.keys(statements).sort();
  if (ids.length !== 5 || ids.some((id, index) => id !== "s" + (index + 1)) || ids.some(id => typeof statements[id] !== "string" || !statements[id].trim())) {
    throw new Error("Input must contain non-empty string values for exactly s1, s2, s3, s4, and s5.");
  }
  const records = ids.map(id => {
    const iv = randomBytes(16);
    const cipher = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
    const ciphertext = Buffer.concat([cipher.update(statements[id], "utf8"), cipher.final()]);
    const mac = createHmac("sha256", key.subarray(32))
      .update(Buffer.concat([Buffer.from(id + "\0", "utf8"), iv, ciphertext]))
      .digest();
    return { key: id, value: JSON.stringify({
      iv: iv.toString("base64"), ciphertext: ciphertext.toString("base64"), mac: mac.toString("base64")
    }) };
  });
  writeFileSync(outputPath, JSON.stringify(records, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  process.stdout.write(`Created encrypted records at ${outputPath}. Keep that file private until upload.\n`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
} finally {
  entered = "";
}
