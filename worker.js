const encoder = new TextEncoder();
const DAY_MS = 24 * 60 * 60 * 1000;
const COOKIE_NAME = "__Host-k4iyo-unlock";
const COOKIE_AGE = 2147483647;
const PASSCODE_ITERATIONS = 600000;

function bytesFromB64(value) {
  const raw = atob(value);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function bytesFromB64url(value) {
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  return bytesFromB64(standard + "=".repeat((4 - standard.length % 4) % 4));
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
async function issueFormToken(id, env) {
  const issuedAt = Date.now().toString();
  const nonce = b64url(randomBytes(16));
  const payload = "gate-form:" + id + ":" + issuedAt + ":" + nonce;
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", await sessionKey(env), encoder.encode(payload)));
  return issuedAt + "." + nonce + "." + b64url(signature);
}
async function verifyFormToken(token, id, env) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3 || !/^\d{13}$/.test(parts[0]) || !/^[A-Za-z0-9_-]{22}$/.test(parts[1]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[2])) return false;
    const issuedAt = Number(parts[0]);
    const now = Date.now();
    if (issuedAt > now + 30000 || now - issuedAt > 10 * 60 * 1000) return false;
    const payload = "gate-form:" + id + ":" + parts[0] + ":" + parts[1];
    return await crypto.subtle.verify("HMAC", await sessionKey(env), bytesFromB64url(parts[2]), encoder.encode(payload));
  } catch { return false; }
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
async function verifyProof(proof, csrf, id, env) {
  const expected = bytesFromB64(String(env.GATE_HASH_B64 || ""));
  if (expected.length !== 32 || !/^[A-Za-z0-9_-]{43}$/.test(String(proof || ""))) return false;
  const key = await hmacKey(expected, ["verify"]);
  return crypto.subtle.verify(
    "HMAC", key, bytesFromB64url(proof), encoder.encode("gate-proof:" + id + ":" + csrf)
  );
}
function passcodeConfigIsValid(env) {
  try {
    return bytesFromB64(String(env.GATE_SALT_B64 || "")).length >= 16 &&
      bytesFromB64(String(env.GATE_HASH_B64 || "")).length === 32;
  } catch { return false; }
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
function statementNavigation(id) {
  const number = Number(id.slice(1));
  const previous = number > 1
    ? '<a href="/s' + (number - 1) + '/" rel="prev">← Previous statement</a>'
    : '<span class="nav-placeholder" aria-hidden="true"></span>';
  const next = number < 5
    ? '<a href="/s' + (number + 1) + '/" rel="next">Next statement →</a>'
    : '<span class="nav-placeholder" aria-hidden="true"></span>';
  return '<nav class="statement-nav" aria-label="Statement navigation">' + previous + '<span class="nav-position">Statement ' + number + ' of 5</span>' + next + '</nav>';
}
async function accessGateHtml(id, env, errorText = "") {
  const formToken = await issueFormToken(id, env);
  const nonce = b64url(randomBytes(16));
  const n = Number(id.slice(1));
  const nav = statementNavigation(id);
  const css = `:root{color-scheme:light;--ink:#252525;--muted:#696969;--rule:#d4d1cb;--paper:#fff;--canvas:#f2f1ee;--accent:#383838}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--canvas);color:var(--ink);font:16px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(100% - 36px,680px);margin:0 auto;padding:clamp(32px,8vw,76px) 0}.mast{padding-bottom:14px;border-bottom:1px solid var(--rule);color:var(--muted);font-size:.7rem;letter-spacing:.16em;text-transform:uppercase}.card{padding:clamp(24px,6vw,48px) 0;border-bottom:1px solid var(--rule)}.eyebrow{color:var(--muted);font-size:.72rem;letter-spacing:.13em;text-transform:uppercase}h1{margin:20px 0 10px;font:500 clamp(2rem,6vw,2.8rem)/1.15 Georgia,"Times New Roman",serif;letter-spacing:-.02em}p{color:#4c4c4c}.field{display:flex;gap:10px;margin-top:22px}.field input{min-width:0;flex:1;padding:12px 13px;border:1px solid #aaa;background:var(--paper);color:var(--ink);font:inherit}.field button,.submit{border:1px solid #666;background:transparent;color:var(--ink);padding:11px 15px;font:600 .88rem -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer}.submit{width:100%;margin-top:12px;background:var(--accent);color:#fff}.submit:disabled{opacity:.6;cursor:wait}.error{color:#7b2525;font-size:.92rem}.subtle{color:var(--muted);font-size:.82rem}.footer{margin-top:24px;color:var(--muted);font-size:.78rem}.statement-nav{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 0;border-bottom:1px solid var(--rule);font-size:.84rem}.statement-nav a,a{color:var(--ink);text-decoration-thickness:1px;text-underline-offset:3px}.statement-nav a:hover,a:hover{color:#666}.nav-position{color:var(--muted);font-size:.74rem;letter-spacing:.06em;text-transform:uppercase}.nav-placeholder{width:8.5rem}@media(max-width:480px){.statement-nav{display:grid;grid-template-columns:1fr 1fr;gap:10px}.nav-position{grid-column:1/-1;grid-row:1;text-align:center}.statement-nav a[rel="prev"],.nav-placeholder:first-child{grid-column:1;grid-row:2}.statement-nav a[rel="next"],.nav-placeholder:last-child{grid-column:2;grid-row:2;justify-self:end}.nav-placeholder{width:auto}}`;
  const script = `const f=document.getElementById('code'),b=document.getElementById('toggle'),form=document.getElementById('gate-form'),submit=form.querySelector('.submit'),status=document.getElementById('verify-status');submit.disabled=false;
function decodeB64(v){const raw=atob(v);return Uint8Array.from(raw,c=>c.charCodeAt(0));}
function encodeB64url(bytes){let raw='';for(const x of bytes)raw+=String.fromCharCode(x);return btoa(raw).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');}
b.addEventListener('click',()=>{const show=f.type==='password';f.type=show?'text':'password';b.textContent=show?'Hide':'Show';b.setAttribute('aria-pressed',String(show));f.focus();});
form.addEventListener('submit',async event=>{if(form.dataset.verified==='true')return;event.preventDefault();if(!f.value||f.value.length>256){f.reportValidity();return;}submit.disabled=true;status.textContent='Checking securely…';try{const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(f.value),'PBKDF2',false,['deriveBits']);const verifier=await crypto.subtle.deriveBits({name:'PBKDF2',salt:decodeB64(form.dataset.salt),iterations:${PASSCODE_ITERATIONS},hash:'SHA-256'},material,256);const key=await crypto.subtle.importKey('raw',verifier,{name:'HMAC',hash:'SHA-256'},false,['sign']);const csrf=form.elements.namedItem('csrf').value;const proof=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode('gate-proof:'+form.dataset.statement+':'+csrf));form.elements.namedItem('proof').value=encodeB64url(new Uint8Array(proof));f.value='';form.dataset.verified='true';form.submit();}catch{submit.disabled=false;status.textContent='Secure code verification failed. Reload and try again.';}});`;
  const csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + nonce + "'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
  const saltB64 = escapeHtml(String(env.GATE_SALT_B64 || ""));
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive,nosnippet"><meta name="theme-color" content="#f2f1ee"><title>Statement ${n} — Private access</title><style>${css}</style></head><body><main><div class="mast">Private statements · Restricted access</div><section class="card"><div class="eyebrow">Statement ${n} of 5</div><h1>Access required</h1><p>This statement is restricted. Enter the access code to continue.</p>${errorText ? '<p class="error" role="alert">' + escapeHtml(errorText) + '</p>' : ''}<noscript><p class="error">Enable JavaScript to securely verify the access code.</p></noscript><form id="gate-form" data-statement="${id}" data-salt="${saltB64}" method="post" action="/s${n}/"><input type="hidden" name="csrf" value="${formToken}"><input type="hidden" name="proof" value=""><label for="code">Access code</label><div class="field"><input id="code" type="password" autocomplete="off" required maxlength="256" aria-describedby="privacy"><button id="toggle" type="button" aria-pressed="false">Show</button></div><button class="submit" type="submit" disabled>Continue</button><p id="verify-status" class="subtle" aria-live="polite"></p></form><p id="privacy" class="subtle">The code is checked in your browser and is not sent in plain text.</p></section>${nav}<p class="footer"><a href="/">Return to k4iyo.com</a> · This page is not indexed by search engines.</p></main><script nonce="${nonce}">${script}</script></body></html>`;
  return new Response(body, { status: 200, headers: headers({
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": csp
  }) });
}
function statementHtml(id, text) {
  const n = Number(id.slice(1));
  const nav = statementNavigation(id);
  const css = `:root{color-scheme:light;--ink:#252525;--muted:#696969;--rule:#d4d1cb;--paper:#fff;--canvas:#f2f1ee;--accent:#383838}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--canvas);color:var(--ink);font:16px/1.8 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(100% - 36px,780px);margin:0 auto;padding:clamp(32px,8vw,76px) 0}.mast{padding-bottom:14px;border-bottom:1px solid var(--rule);color:var(--muted);font-size:.7rem;letter-spacing:.16em;text-transform:uppercase}.card{padding:clamp(26px,6vw,54px) 0}.eyebrow{color:var(--muted);font-size:.72rem;letter-spacing:.13em;text-transform:uppercase}h1{margin:18px 0 30px;font:500 clamp(2rem,6vw,3rem)/1.15 Georgia,"Times New Roman",serif;letter-spacing:-.02em}.statement{font:1.08rem/1.9 Georgia,"Times New Roman",serif;white-space:pre-wrap}.notice{margin:28px 0 0;padding:14px 0;border-top:1px solid var(--rule);color:#555;font-size:.86rem}.statement-nav{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);font-size:.84rem}.statement-nav a,a{color:var(--ink);text-decoration-thickness:1px;text-underline-offset:3px}.statement-nav a:hover,a:hover{color:#666}.nav-position{color:var(--muted);font-size:.74rem;letter-spacing:.06em;text-transform:uppercase}.nav-placeholder{width:8.5rem}footer{margin-top:22px;color:var(--muted);font-size:.78rem}@media(max-width:480px){.statement-nav{display:grid;grid-template-columns:1fr 1fr;gap:10px}.nav-position{grid-column:1/-1;grid-row:1;text-align:center}.statement-nav a[rel="prev"],.nav-placeholder:first-child{grid-column:1;grid-row:2}.statement-nav a[rel="next"],.nav-placeholder:last-child{grid-column:2;grid-row:2;justify-self:end}.nav-placeholder{width:auto}}`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive,nosnippet"><meta name="theme-color" content="#f2f1ee"><title>Statement ${n} — Private</title><style>${css}</style></head><body><main><div class="mast">Private statements · Restricted</div><article class="card"><div class="eyebrow">Statement ${n} of 5</div><h1>A personal statement</h1><div class="statement">${escapeHtml(text)}</div><p class="notice">This page presents the author’s account and allegations as personal statements, not as findings by a court or public authority.</p></article>${nav}<footer><a href="/">Return to k4iyo.com</a> · Shared by invitation</footer></main></body></html>`;
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
      try { await this.storage.setAlarm(record.blockedUntil || record.windowStart + DAY_MS); }
      catch { /* Expiry is enforced from timestamps on the next request if alarm scheduling fails. */ }
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
    if (!env.GATE_LIMITER || !env.SESSION_SIGNING_KEY_B64 || !passcodeConfigIsValid(env)) return textResponse(503, "Secure access is not configured.");
    let state;
    try { state = await limiter(request, env, "check"); }
    catch (error) {
      console.error("gate-access-failure", "limiter-check", error?.name || "Error");
      return textResponse(503, "Secure access is not available.");
    }
    if (state.blocked) return redirect("/");
    if (request.method === "POST") {
      const contentType = (request.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase();
      if (contentType !== "application/x-www-form-urlencoded") return textResponse(415, "Unsupported form encoding.");
      let body;
      try { body = await request.arrayBuffer(); }
      catch { return textResponse(400, "Enter the access code and try again."); }
      if (body.byteLength > 2048) return textResponse(413, "Request too large.");
      let form;
      try { form = new URLSearchParams(new TextDecoder("utf-8", { fatal: true }).decode(body)); }
      catch { return textResponse(400, "Enter the access code and try again."); }
      if (!(await verifyFormToken(form.get("csrf"), id, env))) return textResponse(403, "This form expired. Reload the page and try again.");
      const csrf = form.get("csrf") || "";
      const proof = form.get("proof") || "";
      let phase = "proof-verification";
      try {
        if (!(await verifyProof(proof, csrf, id, env))) {
          phase = "failure-counter";
          const result = await limiter(request, env, "fail");
          if (result.blocked) return redirect("/");
          return await accessGateHtml(id, env, "That code did not match. " + result.attemptsLeft + " attempts remain before a 24-hour lockout.");
        }
        phase = "success-counter";
        await limiter(request, env, "success");
        phase = "success-log";
        await logSuccess(env);
        phase = "session-cookie";
        return redirect("/" + id + "/", { "Set-Cookie": cookieHeader(await issueSession(env)) });
      } catch (error) {
        console.error("gate-access-failure", phase, error?.name || "Error");
        return textResponse(503, "Secure access is not available.");
      }
    }
    if (request.method !== "GET" && request.method !== "HEAD") return textResponse(405, "Method not allowed.", { "Allow": "GET, HEAD, POST" });
    try {
      if (await hasSession(request, env)) return renderStatement(id, env);
      const gate = await accessGateHtml(id, env);
      return request.method === "HEAD" ? new Response(null, { status: 200, headers: gate.headers }) : gate;
    } catch { return textResponse(503, "Secure access is not available."); }
  }
};
