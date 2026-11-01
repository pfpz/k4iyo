#!/usr/bin/env node
import { pbkdf2Sync, randomBytes } from "node:crypto";

if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
  console.error("Run this script in an interactive terminal so the access code is not echoed.");
  process.exit(2);
}
process.stdout.write("Enter the private access code (input hidden): ");
process.stdin.setRawMode(true);
process.stdin.setEncoding("utf8");
process.stdin.resume();
let code = "";
const supplied = await new Promise(resolve => {
  process.stdin.on("data", chunk => {
    for (const char of chunk) {
      if (char === "\u0003") {
        process.stdin.setRawMode(false);
        process.exit(130);
      }
      if (char === "\r" || char === "\n") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write("\n");
        resolve(code);
        return;
      }
      if (char === "\u007f" || char === "\b") code = code.slice(0, -1);
      else if (code.length < 256) code += char;
    }
  });
});
if (!supplied) {
  console.error("The access code cannot be empty.");
  process.exit(2);
}
const salt = randomBytes(16);
const digest = pbkdf2Sync(supplied, salt, 600000, 32, "sha256");
process.stdout.write(JSON.stringify({
  GATE_SALT_B64: salt.toString("base64"),
  GATE_HASH_B64: digest.toString("base64")
}) + "\n");
