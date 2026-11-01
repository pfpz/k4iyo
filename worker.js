const encoder = new TextEncoder();
let jwksCache = { fetchedAt: 0, domain: "", keys: [] };

function b64(text) {
  const raw = atob(text);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function b64url(text) {
  const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
  return b64(normalized + "=".repeat((4 - normalized.length % 4) % 4));
}
function secureHeaders(extra = {}) {
  return {
    "Cache-Control": "private, no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ...extra
  };
}
function textResponse(status, message) {
  return new Response(message, { status, headers: secureHeaders({ "Content-Type": "text/plain; charset=utf-8" }) });
}
function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid token");
  return {
    header: JSON.parse(new TextDecoder().decode(b64url(parts[0]))),
    payload: JSON.parse(new TextDecoder().decode(b64url(parts[1]))),
    signingInput: encoder.encode(parts[0] + "." + parts[1]),
    signature: b64url(parts[2])
  };
}
async function getJwk(domain, kid) {
  const now = Date.now();
  if (jwksCache.domain !== domain || now - jwksCache.fetchedAt > 300000) {
    const response = await fetch("https://" + domain + "/cdn-cgi/access/certs", {
      headers: { "Accept": "application/json" }
    });
    if (!response.ok) throw new Error("key service unavailable");
    const body = await response.json();
    jwksCache = { fetchedAt: now, domain, keys: Array.isArray(body.keys) ? body.keys : [] };
  }
  return jwksCache.keys.find(key => key.kid === kid && key.kty === "RSA");
}
async function verifyAccess(request, env) {
  const domain = String(env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/$/, "");
  const audience = String(env.ACCESS_AUD || "");
  if (!domain || !audience || !/^[a-z0-9.-]+$/i.test(domain)) return false;
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;
  try {
    const jwt = parseJwt(token);
    if (jwt.header.alg !== "RS256" || !jwt.header.kid) return false;
    if (jwt.payload.iss !== "https://" + domain) return false;
    const audiences = Array.isArray(jwt.payload.aud) ? jwt.payload.aud : [jwt.payload.aud];
    if (!audiences.includes(audience)) return false;
    const now = Math.floor(Date.now() / 1000);
    if (typeof jwt.payload.exp !== "number" || jwt.payload.exp <= now) return false;
    if (typeof jwt.payload.nbf === "number" && jwt.payload.nbf > now + 30) return false;
    const jwk = await getJwk(domain, jwt.header.kid);
    if (!jwk) return false;
    const publicKey = await crypto.subtle.importKey("jwk", jwk, {
      name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"
    }, false, ["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, jwt.signature, jwt.signingInput);
  } catch {
    return false;
  }
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
async function decryptRecord(id, record, keyB64) {
  const key = b64(keyB64);
  if (key.length !== 64) throw new Error("invalid key");
  const iv = b64(record.iv);
  const ciphertext = b64(record.ciphertext);
  const mac = b64(record.mac);
  if (iv.length !== 16 || mac.length !== 32 || ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new Error("invalid record");
  }
  const macKey = await crypto.subtle.importKey("raw", key.slice(32), {
    name: "HMAC", hash: "SHA-256"
  }, false, ["verify"]);
  const authenticated = concat(concat(encoder.encode(id + "\0"), iv), ciphertext);
  if (!(await crypto.subtle.verify("HMAC", macKey, mac, authenticated))) throw new Error("authentication failed");
  const aesKey = await crypto.subtle.importKey("raw", key.slice(0, 32), { name: "AES-CBC" }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aesKey, ciphertext);
  return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}
function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}
function htmlFor(id, text) {
  const n = id.slice(1);
  const css = ':root{--ink:#302934;--muted:#756b78;--pink:#c982a5;--line:#eadde6;--paper:#fffdfd}*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.8 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 5%,rgba(248,220,235,.58),transparent 34rem),radial-gradient(ellipse at 94% 88%,rgba(220,237,248,.48),transparent 36rem),var(--paper)}main{width:min(100% - 32px,820px);margin:auto;padding:42px 0}.mast{text-align:center;color:#a36f96;font-size:.7rem;letter-spacing:.22em;text-transform:uppercase}.card{margin-top:26px;padding:clamp(24px,6vw,54px);border:1px solid var(--line);border-radius:18px;background:#fff;box-shadow:0 8px 28px rgba(70,48,65,.045)}.eyebrow{color:#965c7d;font-size:.72rem;font-weight:650;letter-spacing:.17em;text-transform:uppercase}h1{margin:12px 0 24px;font:600 clamp(2rem,6vw,3rem)/1.15 "Iowan Old Style","Palatino Linotype",Georgia,serif}.statement{font:1.08rem/1.9 Georgia,"Times New Roman",serif;white-space:pre-wrap}.notice{margin:24px 0 0;padding:13px 16px;border-left:3px solid var(--pink);background:#fff6fb;color:#655867;font-size:.86rem}footer{margin-top:20px;text-align:center;color:var(--muted);font-size:.75rem;letter-spacing:.07em}';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive,nosnippet"><meta name="theme-color" content="#fffdfd"><title>Private Statement ' + n + ' — KILLKAIYO</title><style>' + css + '</style></head><body><main><div class="mast">KILLKAIYO · PRIVATE STATEMENT</div><article class="card"><div class="eyebrow">Statement ' + n + '</div><h1>A personal statement</h1><div class="statement">' + escapeHtml(text) + '</div><p class="notice">This private page contains the author’s account and allegations. They are presented as the author’s statements, not as findings by a court or public authority.</p></article><footer>Shared by invitation · Please do not redistribute</footer></main></body></html>';
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/s([1-5])(?:\/index\.html)?\/?$/);
    if (!match) return textResponse(404, "Not found.");
    if (!(await verifyAccess(request, env))) return textResponse(401, "Sign-in required.");
    const id = "s" + match[1];
    if (!env.STATEMENTS || !env.STATEMENT_KEY_B64) return textResponse(503, "Secure statement storage is not configured.");
    try {
      const stored = await env.STATEMENTS.get(id);
      if (!stored) return textResponse(404, "Statement unavailable.");
      const statement = await decryptRecord(id, JSON.parse(stored), env.STATEMENT_KEY_B64);
      return new Response(htmlFor(id, statement), {
        status: 200,
        headers: secureHeaders({ "Content-Type": "text/html; charset=utf-8" })
      });
    } catch {
      return textResponse(503, "Statement unavailable.");
    }
  }
};