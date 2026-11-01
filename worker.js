const encoder = new TextEncoder();
const DAY_MS = 24 * 60 * 60 * 1000;
const COOKIE_NAME = "__Host-k4iyo-unlock";
const COOKIE_AGE = 2147483647;
const PASSCODE_ITERATIONS = 600000;

function bytesFromB64(value) {
  const raw = atob(value);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a); out.set(b, a.length); return out;
}
function headers(extra = {}) {
  return {
    "Cache-Control": "private, no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    ...extra
  };
}
function textResponse(status, message, extra = {}) {
  return new Response(message, { status, headers: headers({ "Content-Type": "text/plain; charset=utf-8", ...extra }) });
}
function isSameOriginForm(request, url) {
  const origin = request.headers.get("Origin");
  if (origin !== null) return origin === url.origin;
  if (request.headers.get("Sec-Fetch-Site") === "same-origin") return true;
  const referrer = request.headers.get("Referer");
  if (!referrer) return false;
  try { return new URL(referrer).origin === url.origin; }
  catch { return false; }
}
function redirect(location, extraHeaders = {}) {
  return new Response(null, { status: 303, headers: headers({ Location: location, ...extraHeaders }) });
}
function randomBytes(size) {
  const bytes = new Uint8Array(size); crypto.getRandomValues(bytes); return bytes;
}
async function hmacKey(raw, usages = ["sign", "verify"]) {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, usages);
}
async function sessionKey(env) {
  const raw = bytesFromB64(String(env.SESSION_SIGNING_KEY_B64 || ""));
  if (raw.length !== 32) throw new Error("session secret unavailable");
  return hmacKey(raw);
}
async function clientKey(request, env) {
  const key = await sessionKey(env);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown-client";
  const digest = await crypto.subtle.sign("HMAC", key, encoder.encode("rate-limit:" + ip));
  return b64url(new Uint8Array(digest));
}
async function limiter(request, env, action) {
  const name = await clientKey(request, env);
  const stub = env.GATE_LIMITER.get(env.GATE_LIMITER.idFromName(name));
  const response = await stub.fetch("https://gate-limiter/" + action, { method: "POST" });
  if (!response.ok) throw new Error("rate limiter unavailable");
  return response.json();
}
async function verifyPasscode(candidate, env) {
  const salt = bytesFromB64(String(env.GATE_SALT_B64 || ""));
  const expected = bytesFromB64(String(env.GATE_HASH_B64 || ""));
  if (salt.length < 16 || expected.length !== 32) throw new Error("passcode verifier unavailable");
  const material = await crypto.subtle.importKey("raw", encoder.encode(candidate), "PBKDF2", false, ["deriveBits"]);
  const actual = new Uint8Array(await crypto.subtle.deriveBits({
    name: "PBKDF2", salt, iterations: PASSCODE_ITERATIONS, hash: "SHA-256"
  }, material, 256));
  let difference = 0;
  for (let i = 0; i < actual.length; i++) difference |= actual[i] ^ expected[i];
  return difference === 0;
}
async function issueSession(env) {
  const key = await sessionKey(env);
  const token = b64url(randomBytes(32));
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode("session:" + token)));
  return token + "." + b64url(signature);
}
async function hasSession(request, env) {
  const rawCookie = request.headers.get("Cookie") || "";
  const match = rawCookie.split(";").map(value => value.trim()).find(value => value.startsWith(COOKIE_NAME + "="));
  if (!match) return false;
  const token = match.slice(COOKIE_NAME.length + 1);
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  try {
    const signature = bytesFromB64(parts[1].replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - parts[1].length % 4) % 4));
    return await crypto.subtle.verify("HMAC", await sessionKey(env), signature, encoder.encode("session:" + parts[0]));
  } catch { return false; }
}
async function decryptRecord(id, record, keyB64) {
  const key = bytesFromB64(keyB64);
  if (key.length !== 64) throw new Error("content key unavailable");
  const iv = bytesFromB64(record.iv);
  const ciphertext = bytesFromB64(record.ciphertext);
  const mac = bytesFromB64(record.mac);
  if (iv.length !== 16 || mac.length !== 32 || ciphertext.length === 0 || ciphertext.length % 16 !== 0) throw new Error("invalid record");
  const authenticated = concat(concat(encoder.encode(id + "\0"), iv), ciphertext);
  if (!(await crypto.subtle.verify("HMAC", await hmacKey(key.slice(32), ["verify"]), mac, authenticated))) throw new Error("record authentication failed");
  const aes = await crypto.subtle.importKey("raw", key.slice(0, 32), { name: "AES-CBC" }, false, ["decrypt"]);
  const clear = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aes, ciphertext);
  return new TextDecoder("utf-8", { fatal: true }).decode(clear);
}
function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}
function accessGateHtml(id, errorText = "") {
  const nonce = b64url(randomBytes(16));
  const n = id.slice(1);
  const css = ':root{--ink:#302934;--muted:#756b78;--pink:#c982a5;--line:#eadde6;--paper:#fffdfd}*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.75 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 5%,rgba(248,220,235,.58),transparent 34rem),radial-gradient(ellipse at 94% 88%,rgba(220,237,248,.48),transparent 36rem),var(--paper)}main{width:min(100% - 32px,650px);margin:auto;padding:clamp(34px,8vw,72px) 0}.mast{text-align:center;color:#a36f96;font-size:.7rem;letter-spacing:.22em;text-transform:uppercase}.card{margin-top:26px;padding:clamp(24px,6vw,48px);border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:0 8px 28px rgba(70,48,65,.045)}.eyebrow{color:#965c7d;font-size:.72rem;font-weight:650;letter-spacing:.17em;text-transform:uppercase}h1{margin:12px 0;font:600 clamp(1.9rem,6vw,2.7rem)/1.15 "Iowan Old Style","Palatino Linotype",Georgia,serif}p{color:#655867}.field{display:flex;gap:10px;margin-top:22px}.field input{min-width:0;flex:1;padding:13px 15px;border:1px solid #eadde6;border-radius:12px;font:inherit}.field button,.submit{border:1px solid #d9bfd0;border-radius:12px;background:#fff8fc;color:#6e4d64;padding:12px 15px;font:600 .9rem -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}.submit{width:100%;margin-top:13px;background:#f9eaf2}.error{color:#8d405d;font-size:.9rem}.subtle{color:var(--muted);font-size:.82rem}.footer{margin-top:19px;text-align:center;color:var(--muted);font-size:.75rem}a{color:#965c7d}';
  const script = "const f=document.getElementById('code');const b=document.getElementById('toggle');b.addEventListener('click',()=>{const show=f.type==='password';f.type=show?'text':'password';b.textContent=show?'Hide':'Show';b.setAttribute('aria-pressed',String(show));f.focus();});";
  const csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + nonce + "'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
  const body = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive,nosnippet"><meta name="theme-color" content="#fffdfd"><title>Private Statement ' + n + ' — KILLKAIYO</title><style>' + css + '</style></head><body><main><div class="mast">KILLKAIYO · PRIVATE STATEMENT</div><section class="card"><div class="eyebrow">Statement ' + n + ' · Restricted</div><h1>Enter the access code</h1><p>These statement pages are shared by invitation. Enter the access code to continue.</p>' + (errorText ? '<p class="error" role="alert">' + escapeHtml(errorText) + '</p>' : '') + '<form method="post" action="/s' + n + '/"><label for="code">Access code</label><div class="field"><input id="code" name="code" type="password" autocomplete="current-password" required maxlength="256" aria-describedby="privacy"><button id="toggle" type="button" aria-pressed="false">Show</button></div><button class="submit" type="submit">Unlock all five statements</button></form><p id="privacy" class="subtle">Your code is checked securely and is not stored in plain text.</p></section><p class="footer"><a href="/">Return to k4iyo.com</a> · This page is not indexed by search engines.</p></main><script nonce="' + nonce + '">' + script + '</script></body></html>';
  return new Response(body, { status: 200, headers: headers({
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": csp
  }) });
}
function statementHtml(id, text) {
  const n = id.slice(1);
  const css = ':root{--ink:#302934;--muted:#756b78;--pink:#c982a5;--line:#eadde6;--paper:#fffdfd}*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.8 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 5%,rgba(248,220,235,.58),transparent 34rem),radial-gradient(ellipse at 94% 88%,rgba(220,237,248,.48),transparent 36rem),var(--paper)}main{width:min(100% - 32px,820px);margin:auto;padding:42px 0}.mast{text-align:center;color:#a36f96;font-size:.7rem;letter-spacing:.22em;text-transform:uppercase}.card{margin-top:26px;padding:clamp(24px,6vw,54px);border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:0 8px 28px rgba(70,48,65,.045)}.eyebrow{color:#965c7d;font-size:.72rem;font-weight:650;letter-spacing:.17em;text-transform:uppercase}h1{margin:12px 0 24px;font:600 clamp(2rem,6vw,3rem)/1.15 "Iowan Old Style","Palatino Linotype",Georgia,serif}.statement{font:1.08rem/1.9 Georgia,"Times New Roman",serif;white-space:pre-wrap}.notice{margin:24px 0 0;padding:13px 16px;border-left:3px solid var(--pink);background:#fff6fb;color:#655867;font-size:.86rem}footer{margin-top:20px;text-align:center;color:var(--muted);font-size:.75rem;letter-spacing:.07em}';
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive,nosnippet"><meta name="theme-color" content="#fffdfd"><title>Private Statement ' + n + ' — KILLKAIYO</title><style>' + css + '</style></head><body><main><div class="mast">KILLKAIYO · PRIVATE STATEMENT</div><article class="card"><div class="eyebrow">Statement ' + n + '</div><h1>A personal statement</h1><div class="statement">' + escapeHtml(text) + '</div><p class="notice">This private page contains the author’s account and allegations. They are presented as the author’s statements, not as findings by a court or public authority.</p></article><footer>Shared by invitation · Please do not redistribute</footer></main></body></html>';
  return new Response(html, { status: 200, headers: headers({ "Content-Type": "text/html; charset=utf-8" }) });
}
async function renderStatement(id, env) {
  if (!env.STATEMENTS || !env.CONTENT_KEY_B64) return textResponse(503, "Secure statement storage is not configured.");
  try {
    const value = await env.STATEMENTS.get(id);
    if (!value) return textResponse(404, "Statement unavailable.");
    return statementHtml(id, await decryptRecord(id, JSON.parse(value), env.CONTENT_KEY_B64));
  } catch { return textResponse(503, "Statement unavailable."); }
}
async function logSuccess(env) {
  if (!env.LOGIN_LOG) throw new Error("audit storage unavailable");
  const now = new Date().toISOString();
  await env.LOGIN_LOG.put("success:" + now + ":" + b64url(randomBytes(16)), JSON.stringify({ at: now }));
}
function cookieHeader(token) {
  return COOKIE_NAME + "=" + token + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=" + COOKIE_AGE;
}
export class GateLimiter {
  constructor(state) { this.storage = state.storage; }
  async fetch(request) {
    const now = Date.now();
    const action = new URL(request.url).pathname.slice(1);
    let record = await this.storage.get("attempts") || { count: 0, windowStart: now, blockedUntil: 0 };
    if (record.blockedUntil > now) return Response.json({ blocked: true, attemptsLeft: 0 });
    if ((record.blockedUntil && record.blockedUntil <= now) || now - record.windowStart >= DAY_MS) record = { count: 0, windowStart: now, blockedUntil: 0 };
    if (action === "fail") {
      record.count += 1;
      if (record.count >= 5) record.blockedUntil = now + DAY_MS;
      await this.storage.put("attempts", record);
      await this.storage.setAlarm(record.blockedUntil || record.windowStart + DAY_MS);
      return Response.json({ blocked: record.blockedUntil > now, attemptsLeft: Math.max(0, 5 - record.count) });
    }
    if (action === "success") {
      await this.storage.delete("attempts");
      return Response.json({ blocked: false, attemptsLeft: 5 });
    }
    await this.storage.put("attempts", record);
    return Response.json({ blocked: false, attemptsLeft: Math.max(0, 5 - record.count) });
  }
  async alarm() { await this.storage.delete("attempts"); }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/s([1-5])(?:\/index\.html)?\/?$/);
    if (!match) return textResponse(404, "Not found.");
    const id = "s" + match[1];
    if (!env.GATE_LIMITER || !env.SESSION_SIGNING_KEY_B64) return textResponse(503, "Secure access is not configured.");
    let state;
    try { state = await limiter(request, env, "check"); }
    catch { return textResponse(503, "Secure access is not available."); }
    if (state.blocked) return redirect("/");
    if (request.method === "POST") {
      if (!isSameOriginForm(request, url)) return textResponse(403, "This request could not be verified.");
      const contentType = (request.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase();
      if (contentType !== "application/x-www-form-urlencoded") return textResponse(415, "Unsupported form encoding.");
      let body;
      try { body = await request.arrayBuffer(); }
      catch { return textResponse(400, "Enter the access code and try again."); }
      if (body.byteLength > 2048) return textResponse(413, "Request too large.");
      let candidate;
      try { candidate = new URLSearchParams(new TextDecoder("utf-8", { fatal: true }).decode(body)).get("code") || ""; }
      catch { return textResponse(400, "Enter the access code and try again."); }
      if (!candidate || candidate.length > 256) return accessGateHtml(id, "Enter the access code and try again.");
      try {
        if (!(await verifyPasscode(candidate, env))) {
          const result = await limiter(request, env, "fail");
          if (result.blocked) return redirect("/");
          return accessGateHtml(id, "That code did not match. " + result.attemptsLeft + " attempts remain before a 24-hour lockout.");
        }
        await limiter(request, env, "success");
        await logSuccess(env);
        return redirect("/" + id + "/", { "Set-Cookie": cookieHeader(await issueSession(env)) });
      } catch { return textResponse(503, "Secure access is not available."); }
    }
    if (request.method !== "GET" && request.method !== "HEAD") return textResponse(405, "Method not allowed.", { "Allow": "GET, HEAD, POST" });
    try {
      if (await hasSession(request, env)) return renderStatement(id, env);
      const gate = accessGateHtml(id);
      return request.method === "HEAD" ? new Response(null, { status: 200, headers: gate.headers }) : gate;
    } catch { return textResponse(503, "Secure access is not available."); }
  }
};
