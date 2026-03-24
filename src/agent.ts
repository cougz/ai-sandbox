import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpAgent } from "agents/mcp";
import { DynamicWorkerExecutor, resolveProvider } from "@cloudflare/codemode";
import { Workspace } from "@cloudflare/shell";
import { stateTools } from "@cloudflare/shell/workers";
import { createWorker } from "@cloudflare/worker-bundler";
import { z } from "zod";
import { domainTools } from "./tools/example";

// ─── Env ──────────────────────────────────────────────────────────────────────

export interface Env {
  LOADER: WorkerLoader;
  SandboxAgent: DurableObjectNamespace;
  STORAGE?: R2Bucket;
  USER_REGISTRY: KVNamespace;
  PUBLIC_URL: string;
  GOOGLE_CLIENT_ID: string;
  ALLOWED_EMAIL_DOMAIN: string;   // e.g. "@cloudflare.com"
  // Secrets (wrangler secret put):
  GOOGLE_CLIENT_SECRET?: string;
  JWT_SECRET?: string;
  ADMIN_SECRET?: string;
  // Dev only:
  DEV_USER_ID?: string;
}

interface UserRecord {
  email: string;
  name: string;
  createdAt: string;
  // clientId kept for legacy service-token fallback; omit for OAuth-only users
  clientId?: string;
}

// ─── Base64url helpers ────────────────────────────────────────────────────────

function b64urlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

// ─── JWT (HMAC-SHA256) ────────────────────────────────────────────────────────

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createJwt(email: string, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header  = b64urlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify({ sub: email, email, iat: now, exp: now + 86400 })));
  const key = await hmacKey(secret);
  const sig = b64urlEncode(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${header}.${payload}`)));
  return `${header}.${payload}.${sig}`;
}

async function verifyJwt(token: string, secret: string): Promise<string | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, payload, sig] = parts;
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC", key,
      b64urlDecode(sig),
      new TextEncoder().encode(`${header}.${payload}`)
    );
    if (!valid) return null;
    const data = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
    if (data.exp < Math.floor(Date.now() / 1000)) return null;
    return data.email as string;
  } catch {
    return null;
  }
}

// ─── PKCE ─────────────────────────────────────────────────────────────────────

async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64urlEncode(hash) === challenge;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function resolveUserEmail(request: Request, env: Env): Promise<string | null> {
  // 1. OAuth Bearer token (primary — OpenCode users after mcp auth)
  const auth = request.headers.get("Authorization");
  if (auth?.startsWith("Bearer ") && env.JWT_SECRET) {
    const email = await verifyJwt(auth.slice(7), env.JWT_SECRET);
    if (email) return email;
  }
  // 2. Cloudflare Access browser header (fallback if Access is also configured)
  const cfEmail = request.headers.get("Cf-Access-Authenticated-User-Email");
  if (cfEmail) return cfEmail;
  // 3. Legacy service token → KV lookup
  const clientId = request.headers.get("CF-Access-Client-Id");
  if (clientId) {
    const email = await env.USER_REGISTRY.get(`client:${clientId}`);
    if (email) return email;
  }
  // 4. Dev fallback (never set in production)
  if (env.DEV_USER_ID) return env.DEV_USER_ID;
  return null;
}

/** Auto-create a user record on first OAuth login if one doesn't exist yet. */
async function ensureUserRecord(email: string, env: Env): Promise<void> {
  const key = `user:${email}`;
  const existing = await env.USER_REGISTRY.get(key);
  if (!existing) {
    const record: UserRecord = {
      email,
      name: email.split("@")[0].replace(".", " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      createdAt: new Date().toISOString(),
    };
    await env.USER_REGISTRY.put(key, JSON.stringify(record));
  }
}

// ─── OAuth 2.0 Authorization Server ──────────────────────────────────────────
//
// Implements the MCP OAuth spec so OpenCode can authenticate with just a URL:
//
//   opencode.jsonc:
//   {
//     "mcp": {
//       "ai-sandbox": { "type": "remote", "url": "https://ai-sandbox.cloudemo.org/mcp" }
//     }
//   }
//
//   Then: opencode mcp auth ai-sandbox
//   → OpenCode opens browser → Google login → token stored → done forever.
//
// Endpoints:
//   GET  /.well-known/oauth-authorization-server  ← OAuth metadata discovery
//   POST /oauth/register                          ← Dynamic client registration (RFC 7591)
//   GET  /oauth/authorize                         ← Redirect user to Google
//   GET  /oauth/callback                          ← Handle Google callback
//   POST /oauth/token                             ← Exchange code for JWT
// ─────────────────────────────────────────────────────────────────────────────

async function handleOAuth(request: Request, env: Env): Promise<Response | null> {
  const url = new URL(request.url);
  const base = env.PUBLIC_URL.replace(/\/$/, "");

  // ── Discovery ───────────────────────────────────────────────────────────────
  if (url.pathname === "/.well-known/oauth-authorization-server") {
    return Response.json({
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      scopes_supported: ["openid", "email"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  }

  // ── Dynamic client registration ─────────────────────────────────────────────
  if (url.pathname === "/oauth/register" && request.method === "POST") {
    const body = await request.json<{ redirect_uris?: string[]; client_name?: string }>().catch(() => ({}));
    const clientId = crypto.randomUUID();
    await env.USER_REGISTRY.put(
      `oauth_client:${clientId}`,
      JSON.stringify({ redirectUris: body.redirect_uris ?? [], name: body.client_name ?? "OpenCode" }),
      { expirationTtl: 86400 * 30 } // 30 days
    );
    return Response.json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: body.redirect_uris ?? [],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }, { status: 201 });
  }

  // ── Authorization — redirect user to Google ─────────────────────────────────
  if (url.pathname === "/oauth/authorize") {
    const clientId      = url.searchParams.get("client_id") ?? "";
    const redirectUri   = url.searchParams.get("redirect_uri") ?? "";
    const state         = url.searchParams.get("state") ?? "";
    const codeChallenge = url.searchParams.get("code_challenge") ?? "";
    const codeMethod    = url.searchParams.get("code_challenge_method") ?? "S256";

    if (!clientId || !redirectUri) {
      return new Response("Missing client_id or redirect_uri", { status: 400 });
    }

    // Store OAuth state so the callback can reconstruct everything
    const oauthState = crypto.randomUUID();
    await env.USER_REGISTRY.put(
      `oauth_state:${oauthState}`,
      JSON.stringify({ clientId, redirectUri, state, codeChallenge, codeMethod }),
      { expirationTtl: 600 } // 10 min
    );

    const googleAuth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuth.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
    googleAuth.searchParams.set("redirect_uri", `${base}/oauth/callback`);
    googleAuth.searchParams.set("response_type", "code");
    googleAuth.searchParams.set("scope", "openid email");
    googleAuth.searchParams.set("state", oauthState);
    googleAuth.searchParams.set("access_type", "offline");
    googleAuth.searchParams.set("prompt", "select_account");

    return Response.redirect(googleAuth.toString(), 302);
  }

  // ── Callback — handle Google's response ────────────────────────────────────
  if (url.pathname === "/oauth/callback") {
    const code  = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error || !code || !state) {
      return new Response(`Google OAuth error: ${error ?? "missing code/state"}`, { status: 400 });
    }

    const stateData = await env.USER_REGISTRY.get<{
      clientId: string; redirectUri: string; state: string;
      codeChallenge: string; codeMethod: string;
    }>(`oauth_state:${state}`, "json");

    if (!stateData) {
      return new Response("OAuth state expired or invalid — please try again", { status: 400 });
    }

    await env.USER_REGISTRY.delete(`oauth_state:${state}`);

    // Exchange Google code for tokens
    if (!env.GOOGLE_CLIENT_SECRET) {
      return new Response("GOOGLE_CLIENT_SECRET not configured", { status: 500 });
    }

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${base}/oauth/callback`,
        grant_type: "authorization_code",
      }),
    });

    if (!tokenRes.ok) {
      return new Response(`Google token exchange failed: ${await tokenRes.text()}`, { status: 502 });
    }

    const tokens = await tokenRes.json<{ id_token?: string; error?: string }>();
    if (!tokens.id_token) {
      return new Response(`No id_token from Google: ${JSON.stringify(tokens)}`, { status: 502 });
    }

    // Decode Google's ID token (we trust it because we exchanged it with our secret)
    // We verify domain without checking the signature (internal tool — Google token exchange suffices)
    const idPayload = JSON.parse(new TextDecoder().decode(b64urlDecode(tokens.id_token.split(".")[1])));
    const email: string = idPayload.email;
    const verified: boolean = idPayload.email_verified;

    if (!verified || !email.endsWith(env.ALLOWED_EMAIL_DOMAIN)) {
      return new Response(
        `Access denied. Only ${env.ALLOWED_EMAIL_DOMAIN} accounts may use this service.`,
        { status: 403 }
      );
    }

    // Auto-provision user record on first login
    await ensureUserRecord(email, env);

    // Create a short-lived authorization code to return to OpenCode
    const authCode = crypto.randomUUID();
    await env.USER_REGISTRY.put(
      `auth_code:${authCode}`,
      JSON.stringify({ email, codeChallenge: stateData.codeChallenge }),
      { expirationTtl: 60 } // 1 min — OpenCode exchanges it immediately
    );

    // Redirect back to OpenCode with the auth code
    const redirect = new URL(stateData.redirectUri);
    redirect.searchParams.set("code", authCode);
    if (stateData.state) redirect.searchParams.set("state", stateData.state);

    return Response.redirect(redirect.toString(), 302);
  }

  // ── Token — exchange auth code for JWT ────────────────────────────────────
  if (url.pathname === "/oauth/token" && request.method === "POST") {
    const body = await request.text();
    const params = new URLSearchParams(body);
    const grantType    = params.get("grant_type");
    const code         = params.get("code") ?? "";
    const codeVerifier = params.get("code_verifier") ?? "";

    if (grantType !== "authorization_code") {
      return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
    }

    const codeData = await env.USER_REGISTRY.get<{ email: string; codeChallenge: string }>(
      `auth_code:${code}`, "json"
    );

    if (!codeData) {
      return Response.json({ error: "invalid_grant", error_description: "Code expired or invalid" }, { status: 400 });
    }

    // Verify PKCE
    if (codeData.codeChallenge) {
      const ok = await verifyPkce(codeVerifier, codeData.codeChallenge);
      if (!ok) return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });
    }

    await env.USER_REGISTRY.delete(`auth_code:${code}`);

    if (!env.JWT_SECRET) {
      return Response.json({ error: "server_error", error_description: "JWT_SECRET not configured" }, { status: 500 });
    }

    const accessToken = await createJwt(codeData.email, env.JWT_SECRET);

    return Response.json({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: 86400,
      scope: "openid email",
    });
  }

  return null; // not an OAuth route
}

// ─── Admin auth ───────────────────────────────────────────────────────────────

function isAdminAuthorized(request: Request, env: Env): boolean {
  return !!env.ADMIN_SECRET && request.headers.get("X-Admin-Key") === env.ADMIN_SECRET;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json" },
  });
}

// ─── Admin REST API ───────────────────────────────────────────────────────────

async function handleAdminApi(request: Request, env: Env): Promise<Response> {
  if (!isAdminAuthorized(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);

  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/admin\/api/, "");
  const method = request.method.toUpperCase();

  if (method === "GET" && path === "/users") {
    const list = await env.USER_REGISTRY.list({ prefix: "user:" });
    const users = await Promise.all(
      list.keys.map(async (k) => {
        const record = await env.USER_REGISTRY.get<UserRecord>(k.name, "json");
        if (!record) return null;
        const stub = env.SandboxAgent.get(env.SandboxAgent.idFromName(`user:${record.email}`));
        let files: { path: string; size: number }[] = [];
        try {
          const res = await stub.fetch(new Request(`${url.origin}/__admin/files`, { method: "GET" }));
          if (res.ok) files = await res.json();
        } catch { /* DO may not exist yet */ }
        return { ...record, fileCount: files.length };
      })
    );
    return jsonResponse(users.filter(Boolean));
  }

  if (method === "POST" && path === "/users") {
    const body = await request.json<{ name?: string; email: string; clientId?: string }>();
    if (!body.email) return jsonResponse({ error: "email is required" }, 400);
    const record: UserRecord = {
      email: body.email,
      name: body.name ?? body.email,
      createdAt: new Date().toISOString(),
      ...(body.clientId ? { clientId: body.clientId } : {}),
    };
    await env.USER_REGISTRY.put(`user:${body.email}`, JSON.stringify(record));
    if (body.clientId) await env.USER_REGISTRY.put(`client:${body.clientId}`, body.email);
    return jsonResponse(record, 201);
  }

  const userMatch = path.match(/^\/users\/([^/]+)(\/.*)?$/);
  if (userMatch) {
    const email = decodeURIComponent(userMatch[1]);
    const sub   = userMatch[2] ?? "";
    const stub  = env.SandboxAgent.get(env.SandboxAgent.idFromName(`user:${email}`));

    if (method === "PUT" && sub === "") {
      const body = await request.json<{ clientId?: string; name?: string }>();
      const existing = await env.USER_REGISTRY.get<UserRecord>(`user:${email}`, "json");
      if (!existing) return jsonResponse({ error: "User not found" }, 404);
      if (existing.clientId) await env.USER_REGISTRY.delete(`client:${existing.clientId}`);
      const updated: UserRecord = { ...existing, ...(body.name ? { name: body.name } : {}), ...(body.clientId ? { clientId: body.clientId } : {}) };
      await env.USER_REGISTRY.put(`user:${email}`, JSON.stringify(updated));
      if (body.clientId) await env.USER_REGISTRY.put(`client:${body.clientId}`, email);
      return jsonResponse(updated);
    }

    if (method === "DELETE" && sub === "") {
      const existing = await env.USER_REGISTRY.get<UserRecord>(`user:${email}`, "json");
      if (!existing) return jsonResponse({ error: "User not found" }, 404);
      if (existing.clientId) await env.USER_REGISTRY.delete(`client:${existing.clientId}`);
      await env.USER_REGISTRY.delete(`user:${email}`);
      return jsonResponse({ deleted: email });
    }

    if (method === "GET" && sub === "/files") {
      const res = await stub.fetch(new Request(`${url.origin}/__admin/files`, { method: "GET" }));
      return res.ok ? jsonResponse(await res.json()) : jsonResponse([], 200);
    }

    if (method === "DELETE" && sub === "/workspace") {
      await stub.fetch(new Request(`${url.origin}/__admin/workspace`, { method: "DELETE" }));
      return jsonResponse({ wiped: email });
    }

    if (method === "DELETE" && sub === "/files") {
      const filePath = url.searchParams.get("path");
      if (!filePath) return jsonResponse({ error: "Missing ?path=" }, 400);
      await stub.fetch(new Request(`${url.origin}/__admin/files?path=${encodeURIComponent(filePath)}`, { method: "DELETE" }));
      return jsonResponse({ deleted: filePath });
    }
  }

  return jsonResponse({ error: "Not found" }, 404);
}

// ─── Admin HTML dashboard ─────────────────────────────────────────────────────

function adminDashboard(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Sandbox — Admin</title>
<style>
html{color-scheme:light}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--cf-orange:#FF4801;--cf-text:#521000;--cf-text-muted:rgba(82,16,0,0.7);
  --cf-text-subtle:rgba(82,16,0,0.4);--cf-bg:#FFFBF5;--cf-bg-card:#FFFDFB;
  --cf-bg-hover:#FEF7ED;--cf-border:#EBD5C1;--cf-border-light:rgba(235,213,193,0.5);
  --cf-success:#16A34A;--cf-error:#DC2626;}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--cf-bg);color:var(--cf-text);line-height:1.6;-webkit-font-smoothing:antialiased}
header{background:var(--cf-bg);height:60px;padding:0 32px;display:flex;align-items:center;
  justify-content:space-between;position:relative}
header::after{content:"";position:absolute;bottom:0;left:0;right:0;height:1px;
  background-image:linear-gradient(to right,var(--cf-border) 50%,transparent 50%);
  background-size:12px 1px;background-repeat:repeat-x}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--cf-text)}
.logo svg{height:26px;color:var(--cf-orange)}
.logo-text{font-size:16px;font-weight:500;letter-spacing:-.02em}
.logo-text span{color:var(--cf-text-muted);font-weight:400}
.main{max-width:1100px;margin:0 auto;padding:40px 32px}
.eyebrow{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--cf-text-muted);margin-bottom:8px}
h1{font-size:28px;font-weight:500;letter-spacing:-.02em;margin-bottom:6px}
.subtitle{font-size:14px;color:var(--cf-text-muted);margin-bottom:40px}
.card{position:relative;background:var(--cf-bg-card);border:1px solid var(--cf-border);margin-bottom:24px}
.cb{position:absolute;width:8px;height:8px;border:1px solid var(--cf-border);border-radius:1.5px;background:var(--cf-bg);z-index:2}
.tl{top:-4px;left:-4px}.tr{top:-4px;right:-4px}.bl{bottom:-4px;left:-4px}.br{bottom:-4px;right:-4px}
.card-hdr{padding:14px 18px;border-bottom:1px solid rgba(235,213,193,.4);display:flex;align-items:center;justify-content:space-between}
.card-hdr-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted)}
.card-body{padding:20px 18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:8px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--cf-text-muted);border-bottom:1px solid var(--cf-border);white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid rgba(235,213,193,.3);vertical-align:middle;color:var(--cf-text-muted)}
td strong{color:var(--cf-text);font-weight:500}tr:last-child td{border-bottom:none}tr:hover td{background:var(--cf-bg-hover)}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:600}
.badge-o{background:rgba(255,72,1,.08);color:var(--cf-orange)}.badge-g{background:rgba(22,163,74,.1);color:var(--cf-success)}.badge-m{background:rgba(235,213,193,.4);color:var(--cf-text-muted)}
button,.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:9999px;font-size:12px;font-weight:500;border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text-muted);cursor:pointer;transition:all .15s ease;font-family:inherit}
button:hover{background:var(--cf-bg-hover);color:var(--cf-text);border-style:dashed}
button.danger{color:var(--cf-error);border-color:rgba(220,38,38,.3)}button.danger:hover{background:rgba(220,38,38,.05)}
button.primary{background:var(--cf-orange);color:#fff;border-color:transparent}button.primary:hover{opacity:.9;border-style:solid}
input{border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text);font-family:inherit;font-size:13px;border-radius:6px;padding:8px 12px;width:100%;outline:none;transition:border-color .15s}
input:focus{border-color:var(--cf-orange);box-shadow:0 0 0 3px rgba(255,72,1,.1)}
label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:5px}
.form-grid{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:12px;align-items:end}
.files-panel{background:var(--cf-bg);border-top:1px solid rgba(235,213,193,.4);padding:12px 18px}
.file-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(235,213,193,.2);font-size:12px}.file-row:last-child{border-bottom:none}
.file-path{color:var(--cf-text);font-family:"SF Mono","Fira Code",monospace;font-size:11px}
.file-link{color:var(--cf-orange);text-decoration:none;font-size:11px;font-weight:500}.file-link:hover{text-decoration:underline}
#auth-overlay{position:fixed;inset:0;background:var(--cf-bg);display:flex;align-items:center;justify-content:center;z-index:100}
.auth-box{background:var(--cf-bg-card);border:1px solid var(--cf-border);padding:32px;width:360px;position:relative}
.toast{position:fixed;bottom:24px;right:24px;background:var(--cf-text);color:var(--cf-bg);padding:10px 18px;border-radius:9999px;font-size:13px;font-weight:500;opacity:0;transition:opacity .2s;pointer-events:none;z-index:200}.toast.show{opacity:1}
.empty{padding:32px;text-align:center;color:var(--cf-text-subtle);font-size:13px}
.auth-note{background:var(--cf-bg-hover);border:1px solid var(--cf-border);padding:12px 14px;font-size:12px;color:var(--cf-text-muted);margin-bottom:20px;line-height:1.6}
.auth-note code{background:rgba(255,72,1,.08);padding:1px 5px;border-radius:3px;font-size:11px;color:var(--cf-text)}
</style>
</head>
<body>
<div id="auth-overlay">
  <div class="auth-box">
    <div class="cb tl"></div><div class="cb tr"></div><div class="cb bl"></div><div class="cb br"></div>
    <div style="margin-bottom:16px"><div class="eyebrow">AI Sandbox Worker</div>
      <div style="font-size:20px;font-weight:500;letter-spacing:-.02em">Admin Dashboard</div></div>
    <div class="auth-note">Users authenticate via Google OAuth — no setup needed.<br>
      Their workspace is created automatically on first login.</div>
    <label for="admin-key">Admin Secret</label>
    <input type="password" id="admin-key" placeholder="Enter ADMIN_SECRET" style="margin-bottom:16px">
    <button class="primary" style="width:100%" onclick="authenticate()">Unlock</button>
    <div id="auth-error" style="color:var(--cf-error);font-size:12px;margin-top:10px;display:none">Incorrect secret</div>
  </div>
</div>

<header>
  <a class="logo" href="#">
    <svg viewBox="0 0 66 30" fill="currentColor"><path d="M52.688 13.028c-.22 0-.437.008-.654.015a.3.3 0 0 0-.102.024.37.37 0 0 0-.236.255l-.93 3.249c-.401 1.397-.252 2.687.422 3.634.618.876 1.646 1.39 2.894 1.45l5.045.306a.45.45 0 0 1 .435.41.5.5 0 0 1-.025.223.64.64 0 0 1-.547.426l-5.242.306c-2.848.132-5.912 2.456-6.987 5.29l-.378 1a.28.28 0 0 0 .248.382h18.054a.48.48 0 0 0 .464-.35c.32-1.153.482-2.344.48-3.54 0-7.22-5.79-13.072-12.933-13.072M44.807 29.578l.334-1.175c.402-1.397.253-2.687-.42-3.634-.62-.876-1.647-1.39-2.896-1.45l-23.665-.306a.47.47 0 0 1-.374-.199.5.5 0 0 1-.052-.434.64.64 0 0 1 .552-.426l23.886-.306c2.836-.131 5.9-2.456 6.975-5.29l1.362-3.6a.9.9 0 0 0 .04-.477C48.997 5.259 42.789 0 35.367 0c-6.842 0-12.647 4.462-14.73 10.665a6.92 6.92 0 0 0-4.911-1.374c-3.28.33-5.92 3.002-6.246 6.318a7.2 7.2 0 0 0 .18 2.472C4.3 18.241 0 22.679 0 28.133q0 .74.106 1.453a.46.46 0 0 0 .457.402h43.704a.57.57 0 0 0 .54-.418"/></svg>
    <span class="logo-text">Cloudflare <span>Sandbox Admin</span></span>
  </a>
  <button onclick="loadUsers()">↻ Refresh</button>
</header>

<div class="main">
  <div class="eyebrow">AI Sandbox Worker</div>
  <h1>User Management</h1>
  <p class="subtitle">Users appear automatically after their first Google login. Manage workspace files and access below.</p>

  <div class="card">
    <div class="cb tl"></div><div class="cb tr"></div><div class="cb bl"></div><div class="cb br"></div>
    <div class="card-hdr"><span class="card-hdr-label">Manually Register User</span>
      <span style="font-size:11px;color:var(--cf-text-subtle)">Optional — OAuth users self-register</span></div>
    <div class="card-body">
      <div class="form-grid">
        <div><label>Display Name</label><input id="new-name" placeholder="Tim Seiffert"></div>
        <div><label>Email</label><input id="new-email" placeholder="tim@cloudflare.com"></div>
        <div><label>Service Token Client-Id (optional)</label><input id="new-clientid" placeholder="abc123.access"></div>
        <button class="primary" onclick="addUser()">Add</button>
      </div>
    </div>
  </div>

  <div class="card" id="users-card">
    <div class="cb tl"></div><div class="cb tr"></div><div class="cb bl"></div><div class="cb br"></div>
    <div class="card-hdr"><span class="card-hdr-label">Users</span><span id="user-count" class="badge badge-m">—</span></div>
    <div id="users-body"><div class="empty">Loading…</div></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let ADMIN_KEY='';const BASE=window.location.origin;
function toast(msg,ok=true){const el=document.getElementById('toast');el.textContent=msg;el.style.background=ok?'var(--cf-text)':'var(--cf-error)';el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2500);}
async function api(path,opts={}){const res=await fetch(BASE+'/admin/api'+path,{...opts,headers:{'X-Admin-Key':ADMIN_KEY,'Content-Type':'application/json',...(opts.headers??{})}});if(!res.ok&&res.status===401){showAuth();return null;}return res;}
async function authenticate(){const key=document.getElementById('admin-key').value.trim();if(!key)return;ADMIN_KEY=key;const res=await api('/users');if(!res){document.getElementById('auth-error').style.display='block';ADMIN_KEY='';return;}sessionStorage.setItem('adminKey',key);document.getElementById('auth-overlay').style.display='none';renderUsers(await res.json());}
function showAuth(){sessionStorage.removeItem('adminKey');document.getElementById('auth-overlay').style.display='flex';}
async function loadUsers(){const res=await api('/users');if(!res)return;renderUsers(await res.json());}
function renderUsers(users){document.getElementById('user-count').textContent=users.length+' users';if(!users.length){document.getElementById('users-body').innerHTML='<div class="empty">No users yet. Add one above or have someone authenticate via Google OAuth.</div>';return;}
const rows=users.map(u=>{const k=btoa(u.email).replace(/=/g,'');return\`<tr id="row-\${k}"><td><strong>\${u.name}</strong></td><td>\${u.email}</td><td>\${new Date(u.createdAt).toLocaleDateString()}</td><td><span class="badge \${u.fileCount>0?'badge-g':'badge-m'}">\${u.fileCount} files</span></td><td style="white-space:nowrap;display:flex;gap:6px;padding:8px 12px"><button onclick="toggleFiles('\${u.email}')">Files</button><button class="danger" onclick="wipeWorkspace('\${u.email}')">Wipe</button><button class="danger" onclick="removeUser('\${u.email}')">Remove</button></td></tr><tr id="files-\${k}" style="display:none"><td colspan="5" style="padding:0"><div class="files-panel" id="fp-\${k}">Loading…</div></td></tr>\`;}).join('');
document.getElementById('users-body').innerHTML=\`<table><thead><tr><th>Name</th><th>Email</th><th>First Login</th><th>Workspace</th><th>Actions</th></tr></thead><tbody>\${rows}</tbody></table>\`;}
async function addUser(){const name=document.getElementById('new-name').value.trim(),email=document.getElementById('new-email').value.trim(),clientId=document.getElementById('new-clientid').value.trim();if(!email){toast('Email required',false);return;}const res=await api('/users',{method:'POST',body:JSON.stringify({name:name||email,email,clientId:clientId||undefined})});if(res?.ok){toast('User added');document.getElementById('new-name').value='';document.getElementById('new-email').value='';document.getElementById('new-clientid').value='';loadUsers();}else toast('Error',false);}
async function removeUser(email){if(!confirm('Remove '+email+'?\\nWorkspace files are NOT deleted.'))return;const res=await api('/users/'+encodeURIComponent(email),{method:'DELETE'});if(res?.ok){toast('Removed');loadUsers();}else toast('Error',false);}
async function wipeWorkspace(email){if(!confirm('Wipe ALL files for '+email+'? This cannot be undone.'))return;const res=await api('/users/'+encodeURIComponent(email)+'/workspace',{method:'DELETE'});if(res?.ok){toast('Workspace wiped');loadUsers();}else toast('Error',false);}
async function toggleFiles(email){const k=btoa(email).replace(/=/g,''),row=document.getElementById('files-'+k),panel=document.getElementById('fp-'+k);if(row.style.display==='none'){row.style.display='';const res=await api('/users/'+encodeURIComponent(email)+'/files');if(!res)return;const files=await res.json();if(!files.length){panel.innerHTML='<div style="color:var(--cf-text-subtle);font-size:12px;padding:4px 0">No files</div>';return;}panel.innerHTML=files.map(f=>{const isHtml=f.path.endsWith('.html');const viewUrl=BASE+'/view?user='+encodeURIComponent(email)+'&file='+encodeURIComponent(f.path);return\`<div class="file-row"><span class="file-path">\${f.path}</span><div style="display:flex;gap:8px;align-items:center">\${isHtml?'<a class="file-link" href="'+viewUrl+'" target="_blank">View ↗</a>':''}<button style="padding:3px 10px;font-size:11px" class="danger" onclick="deleteFile('\${email}','\${f.path}')">Delete</button></div></div>\`;}).join('');}else row.style.display='none';}
async function deleteFile(email,path){if(!confirm('Delete '+path+'?'))return;const res=await api('/users/'+encodeURIComponent(email)+'/files?path='+encodeURIComponent(path),{method:'DELETE'});if(res?.ok){toast('Deleted');const k=btoa(email).replace(/=/g,'');document.getElementById('files-'+k).style.display='none';toggleFiles(email);}else toast('Error',false);}
window.addEventListener('load',()=>{const saved=sessionStorage.getItem('adminKey');if(saved){document.getElementById('admin-key').value=saved;authenticate();}});
document.getElementById('admin-key').addEventListener('keydown',e=>{if(e.key==='Enter')authenticate();});
</script>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// ─── MCP Providers ────────────────────────────────────────────────────────────

const domainProvider = { tools: domainTools } as const;

function makeGitprismProvider() {
  return {
    name: "gitprism",
    tools: {
      ingest_repo: {
        description: [
          "Convert any public GitHub repository into LLM-ready Markdown.",
          "Args: { url: string (GitHub URL or owner/repo shorthand),",
          "        detail?: 'summary' | 'structure' | 'file-list' | 'full' (default: 'full') }",
        ].join("\n"),
        execute: async (args: unknown) => {
          const { url, detail = "full" } = args as { url: string; detail?: string };
          const client = new Client({ name: "ai-sandbox", version: "1.0.0" });
          const transport = new StreamableHTTPClientTransport(new URL("https://gitprism.cloudemo.org/mcp"));
          await client.connect(transport);
          try {
            const result = await client.callTool({ name: "ingest_repo", arguments: { url, detail } });
            const content = (result.content as Array<{ type: string; text?: string }>)[0];
            return content?.type === "text" ? content.text : JSON.stringify(content);
          } finally {
            await client.close();
          }
        },
      },
    },
  };
}

const CONTENT_TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  md: "text/markdown; charset=utf-8",
  txt: "text/plain; charset=utf-8",
  csv: "text/csv; charset=utf-8",
};

// ─── SandboxAgent DO ──────────────────────────────────────────────────────────

export class SandboxAgent extends McpAgent<Env, Record<string, never>, {}> {
  server = new McpServer({ name: "ai-sandbox", version: "1.0.0" });

  workspace = new Workspace({
    sql: this.ctx.storage.sql,
    r2: this.env.STORAGE,
    name: () => this.name,
  });

  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Serve a workspace file (public — no auth)
    if (url.pathname === "/view") {
      const file = url.searchParams.get("file") ?? "/reports/dashboard.html";
      const content = await this.workspace.readFile(file);
      if (content === null) return new Response(`File not found: ${file}`, { status: 404 });
      const ext = file.split(".").pop()?.toLowerCase() ?? "txt";
      return new Response(content, { headers: { "Content-Type": CONTENT_TYPES[ext] ?? "text/plain; charset=utf-8" } });
    }

    // Admin: list workspace files
    if (url.pathname === "/__admin/files" && request.method === "GET") {
      try {
        const files = await this.workspace.glob("/**/*");
        const withSizes = await Promise.all(
          files.map(async (path) => {
            const stat = await this.workspace.stat(path);
            return { path, size: stat?.size ?? 0 };
          })
        );
        return new Response(JSON.stringify(withSizes), { headers: { "Content-Type": "application/json" } });
      } catch {
        return new Response("[]", { headers: { "Content-Type": "application/json" } });
      }
    }

    // Admin: delete a specific file
    if (url.pathname === "/__admin/files" && request.method === "DELETE") {
      const path = url.searchParams.get("path");
      if (!path) return new Response("Missing ?path=", { status: 400 });
      await this.workspace.rm(path);
      return new Response(JSON.stringify({ deleted: path }), { headers: { "Content-Type": "application/json" } });
    }

    // Admin: wipe entire workspace
    if (url.pathname === "/__admin/workspace" && request.method === "DELETE") {
      try {
        const files = await this.workspace.glob("/**/*");
        await Promise.all(files.map((f) => this.workspace.rm(f)));
      } catch { /* already empty */ }
      return new Response(JSON.stringify({ wiped: true }), { headers: { "Content-Type": "application/json" } });
    }

    return new Response("Not found", { status: 404 });
  }

  async init() {
    // ── run_code ──────────────────────────────────────────────────────────────
    this.server.tool(
      "run_code",
      [
        "Execute JavaScript code in an isolated V8 sandbox (~2ms startup, no network).",
        "",
        "Available in sandbox:",
        "  state.*     — filesystem ops: readFile, writeFile, glob, searchFiles,",
        "                replaceInFiles, diff, readJson, writeJson, walkTree, ...",
        "  codemode.*  — domain tools: " + Object.keys(domainTools).join(", "),
        "  gitprism.*  — ingest_repo({ url, detail? })",
        "                Converts a public GitHub repo to Markdown.",
        "                detail: 'summary' | 'structure' | 'file-list' | 'full'",
        "",
        "Files written via state.* persist permanently across all sessions for this user.",
        "The code must be an async arrow function or a block of statements.",
      ].join("\n"),
      { code: z.string().describe("JavaScript to run. Can use state.*, codemode.*, and gitprism.*") },
      async ({ code }) => {
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          resolveProvider(makeGitprismProvider()),
        ]);
        return { content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }] };
      }
    );

    // ── run_bundled_code ──────────────────────────────────────────────────────
    this.server.tool(
      "run_bundled_code",
      [
        "Like run_code, but installs npm packages at runtime so the sandbox can import them.",
        "Prefer run_code for tasks that don't need external packages — it's much faster.",
        "Use dynamic import(): const { chunk } = await import('lodash');",
        "state.*, codemode.*, and gitprism.* are available exactly as in run_code.",
      ].join("\n"),
      {
        code: z.string().describe("JavaScript to run. Use dynamic import() to load declared packages."),
        packages: z.record(z.string()).optional().describe("npm packages: { name: versionRange }"),
      },
      async ({ code, packages }) => {
        const { modules: bundledModules } = await createWorker({
          files: {
            "src/entry.ts": Object.keys(packages ?? {}).map((p) => `import "${p}";`).join("\n") || "export {}",
            ...(packages ? { "package.json": JSON.stringify({ dependencies: packages }) } : {}),
          },
        });
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null, modules: bundledModules as Record<string, string> });
        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          resolveProvider(makeGitprismProvider()),
        ]);
        return { content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }] };
      }
    );

    // ── get_report_url ────────────────────────────────────────────────────────
    this.server.tool(
      "get_report_url",
      [
        "Get a shareable browser URL for a file written to the workspace.",
        "Use this after generating an HTML report with run_code.",
        "The URL is stable — tied to your user identity, not the current session.",
      ].join("\n"),
      { file: z.string().default("/reports/dashboard.html").describe("Workspace path, e.g. /reports/dashboard.html") },
      async ({ file }) => {
        const base = this.env.PUBLIC_URL.replace(/\/$/, "");
        const userEmail = this.name.replace(/^user:/, "");
        const url = `${base}/view?user=${encodeURIComponent(userEmail)}&file=${encodeURIComponent(file)}`;
        return { content: [{ type: "text" as const, text: url }] };
      }
    );
  }
}

// ─── Worker fetch handler ─────────────────────────────────────────────────────
//
// Authentication flow for OpenCode users:
//
//   1. Add to opencode.jsonc:
//        "mcp": { "ai-sandbox": { "type": "remote", "url": "https://ai-sandbox.cloudemo.org/mcp" } }
//
//   2. First time only:
//        opencode mcp auth ai-sandbox
//      → OpenCode opens browser → Google login → token stored automatically
//
//   3. All future requests use the stored JWT token — no further action needed.
//
// User records are created automatically on first login.
// No Cloudflare Access or service tokens required.

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // ── OAuth endpoints (unauthenticated — part of the auth flow) ────────────
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // ── Admin dashboard ──────────────────────────────────────────────────────
    if (url.pathname === "/admin") return adminDashboard();

    // ── Admin API ────────────────────────────────────────────────────────────
    if (url.pathname.startsWith("/admin/api")) return handleAdminApi(request, env);

    // ── MCP endpoint ─────────────────────────────────────────────────────────
    if (url.pathname.startsWith("/mcp")) {
      const email = await resolveUserEmail(request, env);
      if (!email) {
        // Return 401 with WWW-Authenticate so OpenCode initiates the OAuth flow
        return new Response("Unauthorized — run: opencode mcp auth ai-sandbox", {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer realm="${env.PUBLIC_URL}", scope="openid email"`,
          },
        });
      }
      const id = env.SandboxAgent.idFromName(`user:${email}`);
      return env.SandboxAgent.get(id).fetch(request);
    }

    // ── View endpoint (public) ───────────────────────────────────────────────
    if (url.pathname === "/view") {
      const userEmail = url.searchParams.get("user");
      // Legacy links used ?session= (the raw MCP session token as DO name)
      const sessionName = url.searchParams.get("session");

      if (userEmail) {
        const id = env.SandboxAgent.idFromName(`user:${userEmail}`);
        return env.SandboxAgent.get(id).fetch(request);
      } else if (sessionName) {
        // Backward compat: route directly by the old DO name
        const id = env.SandboxAgent.idFromName(sessionName);
        return env.SandboxAgent.get(id).fetch(request);
      } else {
        return new Response("Missing query param: ?user=EMAIL or ?session=SESSION", { status: 400 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
