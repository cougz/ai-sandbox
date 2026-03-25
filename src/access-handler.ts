import { Buffer } from "node:buffer";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Workspace } from "@cloudflare/shell";
import {
  addApprovedClient,
  createOAuthState,
  fetchUpstreamAuthToken,
  generateCSRFProtection,
  getUpstreamAuthorizeUrl,
  isClientApproved,
  OAuthError,
  type Props,
  renderApprovalDialog,
  validateCSRFToken,
  validateOAuthState,
} from "./workers-oauth-utils";

// ─── Types ────────────────────────────────────────────────────────────────────

type EnvWithOAuth = Env & { OAUTH_PROVIDER: OAuthHelpers };

interface UserRecord {
  email: string;
  name: string;
  createdAt: string;
}

// ─── Content types for /view ──────────────────────────────────────────────────

const CONTENT_TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  md:   "text/markdown; charset=utf-8",
  txt:  "text/plain; charset=utf-8",
  csv:  "text/csv; charset=utf-8",
};

// ─── Default request handler ──────────────────────────────────────────────────
// Handles everything that is NOT /mcp:
//   /authorize, /callback  ← Access OAuth flow
//   /view                  ← public workspace file viewer (personal or shared)
//   /admin                 ← admin dashboard
//   /admin/api/*           ← admin REST API

export async function handleRequest(
  request: Request,
  env: EnvWithOAuth,
  _ctx: ExecutionContext,
): Promise<Response> {
  const { pathname, searchParams } = new URL(request.url);

  // ── OAuth: show approval dialog ──────────────────────────────────────────
  if (request.method === "GET" && pathname === "/authorize") {
    const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
    if (!oauthReqInfo.clientId) return new Response("Invalid request", { status: 400 });

    if (await isClientApproved(request, oauthReqInfo.clientId, env.COOKIE_ENCRYPTION_KEY)) {
      const { stateToken } = await createOAuthState(oauthReqInfo, env.OAUTH_KV);
      return redirectToAccess(request, env, stateToken);
    }

    const { token: csrfToken, setCookie } = generateCSRFProtection();
    return renderApprovalDialog(request, {
      client: await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId),
      csrfToken,
      server: {
        description: "AI Sandbox — run code, analyse data, generate reports.",
        logo: "https://www.cloudflare.com/favicon.ico",
        name: "Cloudflare AI Sandbox",
      },
      setCookie,
      state: { oauthReqInfo },
    });
  }

  // ── OAuth: handle approval form submit ────────────────────────────────────
  if (request.method === "POST" && pathname === "/authorize") {
    try {
      const formData = await request.formData();
      validateCSRFToken(formData, request);

      const encodedState = formData.get("state");
      if (!encodedState || typeof encodedState !== "string")
        return new Response("Missing state", { status: 400 });

      let state: { oauthReqInfo?: AuthRequest };
      try { state = JSON.parse(atob(encodedState)); }
      catch { return new Response("Invalid state", { status: 400 }); }

      if (!state.oauthReqInfo?.clientId) return new Response("Invalid request", { status: 400 });

      const approvedCookie = await addApprovedClient(request, state.oauthReqInfo.clientId, env.COOKIE_ENCRYPTION_KEY);
      const { stateToken } = await createOAuthState(state.oauthReqInfo, env.OAUTH_KV);

      return redirectToAccess(request, env, stateToken, { "Set-Cookie": approvedCookie });
    } catch (err: unknown) {
      if (err instanceof OAuthError) return err.toResponse();
      return new Response(`Internal error: ${(err as Error).message}`, { status: 500 });
    }
  }

  // ── OAuth: callback from Access ───────────────────────────────────────────
  if (request.method === "GET" && pathname === "/callback") {
    let oauthReqInfo: AuthRequest;
    try {
      ({ oauthReqInfo } = await validateOAuthState(request, env.OAUTH_KV));
    } catch (err: unknown) {
      if (err instanceof OAuthError) return err.toResponse();
      return new Response("Internal error", { status: 500 });
    }

    if (!oauthReqInfo.clientId) return new Response("Invalid OAuth request", { status: 400 });

    const [accessToken, idToken, errResp] = await fetchUpstreamAuthToken({
      client_id: env.ACCESS_CLIENT_ID,
      client_secret: env.ACCESS_CLIENT_SECRET,
      code: searchParams.get("code") ?? undefined,
      redirect_uri: new URL("/callback", request.url).href,
      upstream_url: env.ACCESS_TOKEN_URL,
    });
    if (errResp) return errResp;

    const claims = await verifyAccessToken(env, idToken!);
    const email: string = claims.email;

    // Auto-provision user record on first login
    await ensureUserRecord(email, claims.name ?? email, env);

    const user: Props = {
      accessToken: accessToken!,
      email,
      login: claims.sub,
      name: claims.name ?? email,
    };

    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      metadata: { label: user.name },
      props: user,
      request: oauthReqInfo,
      scope: oauthReqInfo.scope,
      userId: claims.sub,
    });

    return Response.redirect(redirectTo, 302);
  }

  // ── Public: serve a workspace file ───────────────────────────────────────
  if (pathname === "/view") {
    const isShared = searchParams.get("shared") === "true";
    const file     = searchParams.get("file") ?? "/reports/dashboard.html";

    let workspace: Workspace;
    if (isShared) {
      workspace = makeSharedWorkspace(env);
    } else {
      const email = searchParams.get("user");
      if (!email) return new Response("Missing ?user=EMAIL", { status: 400 });
      workspace = makeWorkspace(email, env);
    }

    const content = await workspace.readFile(file);
    if (content === null) return new Response(`File not found: ${file}`, { status: 404 });
    const ext = file.split(".").pop()?.toLowerCase() ?? "txt";
    return new Response(content, {
      headers: { "Content-Type": CONTENT_TYPES[ext] ?? "text/plain; charset=utf-8" },
    });
  }

  // ── Admin dashboard ───────────────────────────────────────────────────────
  if (pathname === "/admin") return adminDashboard();

  // ── Admin API ─────────────────────────────────────────────────────────────
  if (pathname.startsWith("/admin/api")) return handleAdminApi(request, env);

  return new Response("Not found", { status: 404 });
}

// ─── Workspace factory (D1-backed) ────────────────────────────────────────────

// Fixed namespace for the team shared workspace — readable and writable by all users.
export const SHARED_NAMESPACE = "team_shared";

// Derives a valid Workspace namespace from an email address.
// Must match the same function in agent.ts — both sides must agree on the namespace.
export function emailToNamespace(email: string): string {
  return "u_" + email.toLowerCase().replace(/[^a-z0-9]/g, "_").replace(/_+/g, "_").replace(/_$/, "").slice(0, 60);
}

// Module-level cache: Workspace registers itself in a WeakMap inside @cloudflare/shell
// and throws if the same (sql-source, namespace) pair is created twice in one isolate.
// Caching here ensures we only ever construct one Workspace per (D1 binding, namespace).
const wsCache = new WeakMap<object, Map<string, Workspace>>();

function makeWorkspace(email: string, env: Env): Workspace {
  const db = env.WORKSPACE_DB as unknown as object;
  let byNs = wsCache.get(db);
  if (!byNs) { byNs = new Map(); wsCache.set(db, byNs); }
  const ns = emailToNamespace(email);
  let ws = byNs.get(ns);
  if (!ws) {
    ws = new Workspace({
      sql: env.WORKSPACE_DB as unknown as SqlStorage,
      namespace: ns,
      r2: env.STORAGE,
      name: () => email,
    });
    byNs.set(ns, ws);
  }
  return ws;
}

export function makeSharedWorkspace(env: Env): Workspace {
  const db = env.WORKSPACE_DB as unknown as object;
  let byNs = wsCache.get(db);
  if (!byNs) { byNs = new Map(); wsCache.set(db, byNs); }
  let ws = byNs.get(SHARED_NAMESPACE);
  if (!ws) {
    ws = new Workspace({
      sql: env.WORKSPACE_DB as unknown as SqlStorage,
      namespace: SHARED_NAMESPACE,
      r2: env.STORAGE,
      name: () => "shared",
    });
    byNs.set(SHARED_NAMESPACE, ws);
  }
  return ws;
}

// ─── User record helpers ──────────────────────────────────────────────────────

async function ensureUserRecord(email: string, displayName: string, env: Env): Promise<void> {
  const existing = await env.USER_REGISTRY.get(`user:${email}`);
  if (!existing) {
    const record: UserRecord = {
      email,
      name: displayName,
      createdAt: new Date().toISOString(),
    };
    await env.USER_REGISTRY.put(`user:${email}`, JSON.stringify(record));
  }
}

// ─── Access OAuth helpers ─────────────────────────────────────────────────────

function redirectToAccess(request: Request, env: Env, stateToken: string, headers: Record<string, string> = {}): Response {
  return new Response(null, {
    status: 302,
    headers: {
      ...headers,
      location: getUpstreamAuthorizeUrl({
        client_id: env.ACCESS_CLIENT_ID,
        redirect_uri: new URL("/callback", request.url).href,
        scope: "openid email profile",
        state: stateToken,
        upstream_url: env.ACCESS_AUTHORIZATION_URL,
      }),
    },
  });
}

async function fetchAccessPublicKey(env: Env, kid: string): Promise<CryptoKey> {
  if (!env.ACCESS_JWKS_URL) throw new Error("ACCESS_JWKS_URL not set");
  const resp = await fetch(env.ACCESS_JWKS_URL);
  const { keys } = await resp.json<{ keys: (JsonWebKey & { kid: string })[] }>();
  const jwk = keys.find(k => k.kid === kid);
  if (!jwk) throw new Error(`No key found for kid=${kid}`);
  return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

async function verifyAccessToken(env: Env, token: string): Promise<Record<string, string>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");
  const header  = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  const key = await fetchAccessPublicKey(env, header.kid);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key,
    Buffer.from(parts[2], "base64url"),
    Buffer.from(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) throw new Error("JWT signature invalid");
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error("JWT expired");
  return payload;
}

// ─── Admin API ────────────────────────────────────────────────────────────────

function isAdmin(request: Request, env: Env): boolean {
  return !!env.ADMIN_SECRET && request.headers.get("X-Admin-Key") === env.ADMIN_SECRET;
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function handleAdminApi(request: Request, env: Env): Promise<Response> {
  if (!isAdmin(request, env)) return jsonResp({ error: "Unauthorized" }, 401);

  const url    = new URL(request.url);
  const path   = url.pathname.replace(/^\/admin\/api/, "");
  const method = request.method.toUpperCase();

  // ── Shared workspace endpoints ─────────────────────────────────────────────

  // GET /shared/files — list all files in the shared workspace
  if (method === "GET" && path === "/shared/files") {
    try {
      const ws = makeSharedWorkspace(env);
      const entries = await ws.glob("/**/*") as Array<{ path: string; type: string; size: number }>;
      const files = entries.filter(e => e.type === "file").map(e => ({ path: e.path, size: e.size }));
      return jsonResp(files);
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  // POST /shared/files — upload a file to the shared workspace
  // Body: { path: string, content: string }
  if (method === "POST" && path === "/shared/files") {
    try {
      const body = await request.json<{ path: string; content: string }>();
      if (!body.path)    return jsonResp({ error: "path is required" }, 400);
      if (body.content === undefined) return jsonResp({ error: "content is required" }, 400);
      const ws = makeSharedWorkspace(env);
      await ws.writeFile(body.path, body.content);
      return jsonResp({ uploaded: body.path });
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  // DELETE /shared/files?path=... — remove a file from the shared workspace
  if (method === "DELETE" && path === "/shared/files") {
    const filePath = url.searchParams.get("path");
    if (!filePath) return jsonResp({ error: "Missing ?path=" }, 400);
    try {
      const ws = makeSharedWorkspace(env);
      await ws.rm(filePath);
      return jsonResp({ deleted: filePath });
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  // ── User endpoints ─────────────────────────────────────────────────────────

  // GET /users
  if (method === "GET" && path === "/users") {
    const list = await env.USER_REGISTRY.list({ prefix: "user:" });
    const users = await Promise.all(list.keys.map(async k => {
      const r = await env.USER_REGISTRY.get<UserRecord>(k.name, "json");
      if (!r) return null;
      // Count workspace files (glob returns file-info objects — filter to files only)
      let fileCount = 0;
      try {
        const ws = makeWorkspace(r.email, env);
        const entries = await ws.glob("/**/*") as Array<{ type: string }>;
        fileCount = entries.filter(e => e.type === "file").length;
      } catch { /* workspace may be empty */ }
      return { ...r, fileCount };
    }));
    return jsonResp(users.filter(Boolean));
  }

  // POST /users
  if (method === "POST" && path === "/users") {
    const body = await request.json<{ name?: string; email: string }>();
    if (!body.email) return jsonResp({ error: "email is required" }, 400);
    await ensureUserRecord(body.email, body.name ?? body.email, env);
    return jsonResp({ email: body.email, name: body.name ?? body.email }, 201);
  }

  const userMatch = path.match(/^\/users\/([^/]+)(\/.*)?$/);
  if (userMatch) {
    const email = decodeURIComponent(userMatch[1]);
    const sub   = userMatch[2] ?? "";

    // DELETE /users/:email — remove from registry (keeps workspace data in D1)
    if (method === "DELETE" && sub === "") {
      await env.USER_REGISTRY.delete(`user:${email}`);
      return jsonResp({ deleted: email });
    }

    const workspace = makeWorkspace(email, env);

    // GET /users/:email/files
    if (method === "GET" && sub === "/files") {
      try {
        // glob() returns file-info objects {path, name, type, size, ...}, not strings
        const entries = await workspace.glob("/**/*") as Array<{ path: string; type: string; size: number }>;
        const files = entries.filter(e => e.type === "file").map(e => ({ path: e.path, size: e.size }));
        return jsonResp(files);
      } catch (err) { return jsonResp({ error: String(err) }, 500); }
    }

    // DELETE /users/:email/workspace
    if (method === "DELETE" && sub === "/workspace") {
      try {
        const entries = await workspace.glob("/**/*") as Array<{ path: string; type: string }>;
        await Promise.all(entries.filter(e => e.type === "file").map(e => workspace.rm(e.path)));
      } catch { /* already empty */ }
      return jsonResp({ wiped: email });
    }

    // DELETE /users/:email/files?path=...
    if (method === "DELETE" && sub === "/files") {
      const filePath = url.searchParams.get("path");
      if (!filePath) return jsonResp({ error: "Missing ?path=" }, 400);
      await workspace.rm(filePath);
      return jsonResp({ deleted: filePath });
    }
  }

  return jsonResp({ error: "Not found" }, 404);
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
:root{--cf-orange:#FF4801;--cf-text:#521000;--cf-text-muted:rgba(82,16,0,0.7);--cf-text-subtle:rgba(82,16,0,0.4);--cf-bg:#FFFBF5;--cf-bg-card:#FFFDFB;--cf-bg-hover:#FEF7ED;--cf-border:#EBD5C1;--cf-success:#16A34A;--cf-error:#DC2626}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--cf-bg);color:var(--cf-text);line-height:1.6;-webkit-font-smoothing:antialiased}
header{background:var(--cf-bg);height:60px;padding:0 32px;display:flex;align-items:center;justify-content:space-between;position:relative}
header::after{content:"";position:absolute;bottom:0;left:0;right:0;height:1px;background-image:linear-gradient(to right,var(--cf-border) 50%,transparent 50%);background-size:12px 1px;background-repeat:repeat-x}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--cf-text)}
.logo svg{height:26px;color:var(--cf-orange)}
.logo-text{font-size:16px;font-weight:500;letter-spacing:-.02em}
.logo-text span{color:var(--cf-text-muted);font-weight:400}
.main{max-width:1100px;margin:0 auto;padding:40px 32px}
.eyebrow{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--cf-text-muted);margin-bottom:8px}
h1{font-size:28px;font-weight:500;letter-spacing:-.02em;margin-bottom:6px}
h2{font-size:20px;font-weight:500;letter-spacing:-.02em;margin-bottom:6px}
.subtitle{font-size:14px;color:var(--cf-text-muted);margin-bottom:40px}
.section{margin-top:48px}
.card{position:relative;background:var(--cf-bg-card);border:1px solid var(--cf-border);margin-bottom:24px}
.cb{position:absolute;width:8px;height:8px;border:1px solid var(--cf-border);border-radius:1.5px;background:var(--cf-bg);z-index:2}
.card-hdr{padding:14px 18px;border-bottom:1px solid rgba(235,213,193,.4);display:flex;align-items:center;justify-content:space-between}
.card-hdr-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted)}
.card-body{padding:20px 18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:8px 12px;text-align:left;font-size:10px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--cf-text-muted);border-bottom:1px solid var(--cf-border);white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid rgba(235,213,193,.3);vertical-align:middle;color:var(--cf-text-muted)}
td strong{color:var(--cf-text);font-weight:500}tr:last-child td{border-bottom:none}tr:hover td{background:var(--cf-bg-hover)}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:600}
.badge-g{background:rgba(22,163,74,.1);color:var(--cf-success)}.badge-m{background:rgba(235,213,193,.4);color:var(--cf-text-muted)}
button{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:9999px;font-size:12px;font-weight:500;border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text-muted);cursor:pointer;transition:all .15s;font-family:inherit}
button:hover{background:var(--cf-bg-hover);color:var(--cf-text);border-style:dashed}
button.danger{color:var(--cf-error);border-color:rgba(220,38,38,.3)}button.danger:hover{background:rgba(220,38,38,.05)}
button.primary{background:var(--cf-orange);color:#fff;border-color:transparent}button.primary:hover{background:#e03d00;border-style:solid}
input,textarea{border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text);font-family:inherit;font-size:13px;border-radius:6px;padding:8px 12px;width:100%;outline:none;transition:border-color .15s}
input:focus,textarea:focus{border-color:var(--cf-orange)}
input[type=file]{padding:6px 10px;cursor:pointer}
textarea{resize:vertical;min-height:120px;font-family:"SF Mono","Fira Code",monospace;font-size:12px}
label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:5px}
.form-row{margin-bottom:14px}
.form-grid{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;align-items:end}
.upload-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.files-panel{background:var(--cf-bg);border-top:1px solid rgba(235,213,193,.4);padding:12px 18px}
.file-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(235,213,193,.2);font-size:12px}.file-row:last-child{border-bottom:none}
.file-path{color:var(--cf-text);font-family:"SF Mono","Fira Code",monospace;font-size:11px}
.file-size{color:var(--cf-text-subtle);font-size:10px;margin-left:8px}
.file-link{color:var(--cf-orange);text-decoration:none;font-size:11px;font-weight:500}.file-link:hover{text-decoration:underline}
#auth-overlay{position:fixed;inset:0;background:var(--cf-bg);display:flex;align-items:center;justify-content:center;z-index:100}
.auth-box{background:var(--cf-bg-card);border:1px solid var(--cf-border);padding:32px;width:360px;position:relative}
.toast{position:fixed;bottom:24px;right:24px;background:var(--cf-text);color:var(--cf-bg);padding:10px 18px;border-radius:9999px;font-size:13px;font-weight:500;opacity:0;transition:opacity .2s;pointer-events:none;z-index:200}.toast.show{opacity:1}
.empty{padding:32px;text-align:center;color:var(--cf-text-subtle);font-size:13px}
.divider{height:1px;background:var(--cf-border);margin:0 0 32px}
</style>
</head>
<body>
<div id="auth-overlay">
  <div class="auth-box">
    <div class="cb" style="top:-4px;left:-4px"></div><div class="cb" style="top:-4px;right:-4px"></div>
    <div class="cb" style="bottom:-4px;left:-4px"></div><div class="cb" style="bottom:-4px;right:-4px"></div>
    <div style="margin-bottom:16px"><div class="eyebrow">AI Sandbox Worker</div>
      <div style="font-size:20px;font-weight:500;letter-spacing:-.02em">Admin Dashboard</div></div>
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
  <button onclick="loadAll()">↻ Refresh</button>
</header>
<div class="main">

  <!-- ── Users ── -->
  <div class="eyebrow">AI Sandbox Worker</div>
  <h1>User Management</h1>
  <p class="subtitle">Users appear automatically after their first Access login. Workspaces are persistent across sessions.</p>
  <div class="card" id="users-card">
    <div class="cb" style="top:-4px;left:-4px"></div><div class="cb" style="top:-4px;right:-4px"></div>
    <div class="cb" style="bottom:-4px;left:-4px"></div><div class="cb" style="bottom:-4px;right:-4px"></div>
    <div class="card-hdr"><span class="card-hdr-label">Users</span><span id="user-count" class="badge badge-m">—</span></div>
    <div id="users-body"><div class="empty">Loading…</div></div>
  </div>

  <!-- ── Shared Workspace ── -->
  <div class="section">
    <div class="eyebrow">Team Resources</div>
    <h2>Shared Workspace</h2>
    <p class="subtitle" style="margin-bottom:24px">Files accessible to all team members via <code style="font-family:monospace;font-size:12px;background:rgba(235,213,193,.4);padding:1px 5px;border-radius:3px">shared.*</code> in the sandbox. Any logged-in user can read and write here.</p>
    <div class="card" id="shared-card">
      <div class="cb" style="top:-4px;left:-4px"></div><div class="cb" style="top:-4px;right:-4px"></div>
      <div class="cb" style="bottom:-4px;left:-4px"></div><div class="cb" style="bottom:-4px;right:-4px"></div>
      <div class="card-hdr">
        <span class="card-hdr-label">Files</span>
        <div style="display:flex;gap:8px;align-items:center">
          <span id="shared-count" class="badge badge-m">—</span>
          <button onclick="loadSharedFiles()" style="padding:4px 12px;font-size:11px">↻ Refresh</button>
        </div>
      </div>
      <!-- Upload form -->
      <div class="card-body" style="border-bottom:1px solid rgba(235,213,193,.4)">
        <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:14px">Upload File</div>
        <div class="upload-grid" style="margin-bottom:12px">
          <div class="form-row" style="margin:0">
            <label for="shared-path">File Path</label>
            <input type="text" id="shared-path" placeholder="/templates/cf-report.html">
          </div>
          <div class="form-row" style="margin:0">
            <label for="shared-file-input">Upload from disk (optional)</label>
            <input type="file" id="shared-file-input" onchange="onSharedFileChosen(this)">
          </div>
        </div>
        <div class="form-row">
          <label for="shared-content">Content <span style="font-weight:400;text-transform:none;letter-spacing:0">(paste text, or pick a file above)</span></label>
          <textarea id="shared-content" placeholder="Paste HTML, JSON, markdown, or any text content here…"></textarea>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button class="primary" onclick="uploadSharedFile()">Upload</button>
          <span id="shared-upload-status" style="font-size:12px;color:var(--cf-text-muted)"></span>
        </div>
      </div>
      <!-- File list -->
      <div id="shared-files-body"><div class="empty">Loading…</div></div>
    </div>
  </div>

</div>
<div class="toast" id="toast"></div>
<script>
let ADMIN_KEY='';const BASE=window.location.origin;
function toast(msg,ok=true){const el=document.getElementById('toast');el.textContent=msg;el.style.background=ok?'var(--cf-text)':'var(--cf-error)';el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2500);}
async function api(path,opts={}){const res=await fetch(BASE+'/admin/api'+path,{...opts,headers:{'X-Admin-Key':ADMIN_KEY,'Content-Type':'application/json',...(opts.headers??{})}});if(res.status===401){showAuth();return null;}return res;}
async function authenticate(){const key=document.getElementById('admin-key').value.trim();if(!key)return;ADMIN_KEY=key;const res=await api('/users');if(!res){document.getElementById('auth-error').style.display='block';ADMIN_KEY='';return;}sessionStorage.setItem('adminKey',key);document.getElementById('auth-overlay').style.display='none';renderUsers(await res.json());loadSharedFiles();}
function showAuth(){sessionStorage.removeItem('adminKey');document.getElementById('auth-overlay').style.display='flex';}
async function loadAll(){await Promise.all([loadUsers(),loadSharedFiles()]);}
async function loadUsers(){const res=await api('/users');if(!res)return;renderUsers(await res.json());}
function renderUsers(users){document.getElementById('user-count').textContent=users.length+' users';if(!users.length){document.getElementById('users-body').innerHTML='<div class="empty">No users yet — they appear automatically after first login.</div>';return;}
const rows=users.map(u=>{const k=btoa(u.email).replace(/=/g,'');return\`<tr id="row-\${k}"><td><strong>\${u.name}</strong></td><td>\${u.email}</td><td>\${new Date(u.createdAt).toLocaleDateString()}</td><td><span class="badge \${u.fileCount>0?'badge-g':'badge-m'}">\${u.fileCount} files</span></td><td style="white-space:nowrap;display:flex;gap:6px;padding:8px 12px"><button onclick="toggleFiles('\${u.email}')">Files</button><button class="danger" onclick="wipeWorkspace('\${u.email}')">Wipe</button><button class="danger" onclick="removeUser('\${u.email}')">Remove</button></td></tr><tr id="files-\${k}" style="display:none"><td colspan="5" style="padding:0"><div class="files-panel" id="fp-\${k}">Loading…</div></td></tr>\`;}).join('');
document.getElementById('users-body').innerHTML=\`<table><thead><tr><th>Name</th><th>Email</th><th>First Login</th><th>Workspace</th><th>Actions</th></tr></thead><tbody>\${rows}</tbody></table>\`;}
async function removeUser(email){if(!confirm('Remove '+email+'? Workspace files in D1 are NOT deleted.'))return;const res=await api('/users/'+encodeURIComponent(email),{method:'DELETE'});if(res?.ok){toast('Removed');loadUsers();}else toast('Error',false);}
async function wipeWorkspace(email){if(!confirm('Wipe ALL files for '+email+'? This cannot be undone.'))return;const res=await api('/users/'+encodeURIComponent(email)+'/workspace',{method:'DELETE'});if(res?.ok){toast('Workspace wiped');loadUsers();}else toast('Error',false);}
async function toggleFiles(email){const k=btoa(email).replace(/=/g,''),row=document.getElementById('files-'+k),panel=document.getElementById('fp-'+k);if(row.style.display==='none'){row.style.display='';const res=await api('/users/'+encodeURIComponent(email)+'/files');if(!res)return;const files=await res.json();if(!files.length){panel.innerHTML='<div style="color:var(--cf-text-subtle);font-size:12px;padding:4px 0">No files</div>';return;}panel.innerHTML=files.map(f=>{const isHtml=f.path.endsWith('.html');const viewUrl=BASE+'/view?user='+encodeURIComponent(email)+'&file='+encodeURIComponent(f.path);return\`<div class="file-row"><span class="file-path">\${f.path}</span><div style="display:flex;gap:8px;align-items:center">\${isHtml?'<a class="file-link" href="'+viewUrl+'" target="_blank">View ↗</a>':''}<button style="padding:3px 10px;font-size:11px" class="danger" onclick="deleteUserFile('\${email}','\${f.path}')">Delete</button></div></div>\`;}).join('');}else row.style.display='none';}
async function deleteUserFile(email,path){if(!confirm('Delete '+path+'?'))return;const res=await api('/users/'+encodeURIComponent(email)+'/files?path='+encodeURIComponent(path),{method:'DELETE'});if(res?.ok){toast('Deleted');const k=btoa(email).replace(/=/g,'');document.getElementById('files-'+k).style.display='none';toggleFiles(email);}else toast('Error',false);}

/* ── Shared workspace ── */
async function loadSharedFiles(){const res=await api('/shared/files');if(!res)return;renderSharedFiles(await res.json());}
function fmtSize(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';}
function renderSharedFiles(files){
  const countEl=document.getElementById('shared-count');
  const bodyEl=document.getElementById('shared-files-body');
  countEl.textContent=files.length+' files';
  if(!files.length){bodyEl.innerHTML='<div class="empty">No files yet — upload a template or resource above.</div>';return;}
  bodyEl.innerHTML='<div style="padding:0 18px">'+files.map(f=>{
    const isHtml=f.path.endsWith('.html');
    const viewUrl=BASE+'/view?shared=true&file='+encodeURIComponent(f.path);
    return\`<div class="file-row">
      <span><span class="file-path">\${f.path}</span><span class="file-size">\${fmtSize(f.size??0)}</span></span>
      <div style="display:flex;gap:8px;align-items:center">
        \${isHtml?'<a class="file-link" href="'+viewUrl+'" target="_blank">View ↗</a>':''}
        <button style="padding:3px 10px;font-size:11px" class="danger" onclick="deleteSharedFile('\${f.path.replace(/'/g,\\"\\'\\")  }')">Delete</button>
      </div>
    </div>\`;
  }).join('')+'</div>';}
function onSharedFileChosen(input){if(!input.files.length)return;const name=input.files[0].name;const pathEl=document.getElementById('shared-path');if(!pathEl.value)pathEl.value='/'+name;}
async function uploadSharedFile(){
  const path=document.getElementById('shared-path').value.trim();
  const fileInput=document.getElementById('shared-file-input');
  let content=document.getElementById('shared-content').value;
  if(!path){toast('File path is required',false);return;}
  const statusEl=document.getElementById('shared-upload-status');
  statusEl.textContent='Uploading…';
  if(fileInput.files.length>0){try{content=await fileInput.files[0].text();}catch{toast('Could not read file',false);statusEl.textContent='';return;}}
  const res=await api('/shared/files',{method:'POST',body:JSON.stringify({path,content})});
  if(res?.ok){
    toast('Uploaded '+path);
    document.getElementById('shared-path').value='';
    document.getElementById('shared-content').value='';
    fileInput.value='';
    statusEl.textContent='';
    loadSharedFiles();
  }else{const err=res?await res.json():null;toast(err?.error||'Upload failed',false);statusEl.textContent='';}
}
async function deleteSharedFile(path){
  if(!confirm('Delete '+path+' from the shared workspace? All team members will lose access.'))return;
  const res=await api('/shared/files?path='+encodeURIComponent(path),{method:'DELETE'});
  if(res?.ok){toast('Deleted');loadSharedFiles();}else toast('Error',false);
}
window.addEventListener('load',()=>{const s=sessionStorage.getItem('adminKey');if(s){document.getElementById('admin-key').value=s;authenticate();}});
document.getElementById('admin-key').addEventListener('keydown',e=>{if(e.key==='Enter')authenticate();});
</script>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
