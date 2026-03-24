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
//   /view                  ← public workspace file viewer
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

    // Domain restriction
    if (!email.endsWith(env.ALLOWED_EMAIL_DOMAIN)) {
      return new Response(`Access denied — only ${env.ALLOWED_EMAIL_DOMAIN} accounts are allowed.`, { status: 403 });
    }

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
    const email = searchParams.get("user");
    const file  = searchParams.get("file") ?? "/reports/dashboard.html";

    if (!email) return new Response("Missing ?user=EMAIL", { status: 400 });

    // Workspaces are backed by D1 — we can read them directly without a DO stub
    const workspace = makeWorkspace(email, env);
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

function makeWorkspace(email: string, env: Env): Workspace {
  return new Workspace({
    sql: env.WORKSPACE_DB as unknown as SqlStorage,
    r2: env.STORAGE,
    name: () => email,
  });
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

  // GET /users
  if (method === "GET" && path === "/users") {
    const list = await env.USER_REGISTRY.list({ prefix: "user:" });
    const users = await Promise.all(list.keys.map(async k => {
      const r = await env.USER_REGISTRY.get<UserRecord>(k.name, "json");
      if (!r) return null;
      // Count workspace files directly via D1-backed workspace
      let fileCount = 0;
      try {
        const ws = makeWorkspace(r.email, env);
        const files = await ws.glob("/**/*");
        fileCount = files.length;
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
        const files = await workspace.glob("/**/*");
        const withSizes = await Promise.all(files.map(async p => {
          const stat = await workspace.stat(p);
          return { path: p, size: stat?.size ?? 0 };
        }));
        return jsonResp(withSizes);
      } catch { return jsonResp([]); }
    }

    // DELETE /users/:email/workspace
    if (method === "DELETE" && sub === "/workspace") {
      try {
        const files = await workspace.glob("/**/*");
        await Promise.all(files.map(f => workspace.rm(f)));
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
.subtitle{font-size:14px;color:var(--cf-text-muted);margin-bottom:40px}
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
button.primary{background:var(--cf-orange);color:#fff;border-color:transparent}
input{border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text);font-family:inherit;font-size:13px;border-radius:6px;padding:8px 12px;width:100%;outline:none;transition:border-color .15s}
input:focus{border-color:var(--cf-orange)}
label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:5px}
.form-grid{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;align-items:end}
.files-panel{background:var(--cf-bg);border-top:1px solid rgba(235,213,193,.4);padding:12px 18px}
.file-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(235,213,193,.2);font-size:12px}.file-row:last-child{border-bottom:none}
.file-path{color:var(--cf-text);font-family:"SF Mono","Fira Code",monospace;font-size:11px}
.file-link{color:var(--cf-orange);text-decoration:none;font-size:11px;font-weight:500}.file-link:hover{text-decoration:underline}
#auth-overlay{position:fixed;inset:0;background:var(--cf-bg);display:flex;align-items:center;justify-content:center;z-index:100}
.auth-box{background:var(--cf-bg-card);border:1px solid var(--cf-border);padding:32px;width:360px;position:relative}
.toast{position:fixed;bottom:24px;right:24px;background:var(--cf-text);color:var(--cf-bg);padding:10px 18px;border-radius:9999px;font-size:13px;font-weight:500;opacity:0;transition:opacity .2s;pointer-events:none;z-index:200}.toast.show{opacity:1}
.empty{padding:32px;text-align:center;color:var(--cf-text-subtle);font-size:13px}
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
  <button onclick="loadUsers()">↻ Refresh</button>
</header>
<div class="main">
  <div class="eyebrow">AI Sandbox Worker</div>
  <h1>User Management</h1>
  <p class="subtitle">Users appear automatically after their first Access login. Workspaces are persistent across sessions.</p>
  <div class="card" id="users-card">
    <div class="cb" style="top:-4px;left:-4px"></div><div class="cb" style="top:-4px;right:-4px"></div>
    <div class="cb" style="bottom:-4px;left:-4px"></div><div class="cb" style="bottom:-4px;right:-4px"></div>
    <div class="card-hdr"><span class="card-hdr-label">Users</span><span id="user-count" class="badge badge-m">—</span></div>
    <div id="users-body"><div class="empty">Loading…</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
let ADMIN_KEY='';const BASE=window.location.origin;
function toast(msg,ok=true){const el=document.getElementById('toast');el.textContent=msg;el.style.background=ok?'var(--cf-text)':'var(--cf-error)';el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2500);}
async function api(path,opts={}){const res=await fetch(BASE+'/admin/api'+path,{...opts,headers:{'X-Admin-Key':ADMIN_KEY,'Content-Type':'application/json',...(opts.headers??{})}});if(res.status===401){showAuth();return null;}return res;}
async function authenticate(){const key=document.getElementById('admin-key').value.trim();if(!key)return;ADMIN_KEY=key;const res=await api('/users');if(!res){document.getElementById('auth-error').style.display='block';ADMIN_KEY='';return;}sessionStorage.setItem('adminKey',key);document.getElementById('auth-overlay').style.display='none';renderUsers(await res.json());}
function showAuth(){sessionStorage.removeItem('adminKey');document.getElementById('auth-overlay').style.display='flex';}
async function loadUsers(){const res=await api('/users');if(!res)return;renderUsers(await res.json());}
function renderUsers(users){document.getElementById('user-count').textContent=users.length+' users';if(!users.length){document.getElementById('users-body').innerHTML='<div class="empty">No users yet — they appear automatically after first login.</div>';return;}
const rows=users.map(u=>{const k=btoa(u.email).replace(/=/g,'');return\`<tr id="row-\${k}"><td><strong>\${u.name}</strong></td><td>\${u.email}</td><td>\${new Date(u.createdAt).toLocaleDateString()}</td><td><span class="badge \${u.fileCount>0?'badge-g':'badge-m'}">\${u.fileCount} files</span></td><td style="white-space:nowrap;display:flex;gap:6px;padding:8px 12px"><button onclick="toggleFiles('\${u.email}')">Files</button><button class="danger" onclick="wipeWorkspace('\${u.email}')">Wipe</button><button class="danger" onclick="removeUser('\${u.email}')">Remove</button></td></tr><tr id="files-\${k}" style="display:none"><td colspan="5" style="padding:0"><div class="files-panel" id="fp-\${k}">Loading…</div></td></tr>\`;}).join('');
document.getElementById('users-body').innerHTML=\`<table><thead><tr><th>Name</th><th>Email</th><th>First Login</th><th>Workspace</th><th>Actions</th></tr></thead><tbody>\${rows}</tbody></table>\`;}
async function removeUser(email){if(!confirm('Remove '+email+'? Workspace files in D1 are NOT deleted.'))return;const res=await api('/users/'+encodeURIComponent(email),{method:'DELETE'});if(res?.ok){toast('Removed');loadUsers();}else toast('Error',false);}
async function wipeWorkspace(email){if(!confirm('Wipe ALL files for '+email+'? This cannot be undone.'))return;const res=await api('/users/'+encodeURIComponent(email)+'/workspace',{method:'DELETE'});if(res?.ok){toast('Workspace wiped');loadUsers();}else toast('Error',false);}
async function toggleFiles(email){const k=btoa(email).replace(/=/g,''),row=document.getElementById('files-'+k),panel=document.getElementById('fp-'+k);if(row.style.display==='none'){row.style.display='';const res=await api('/users/'+encodeURIComponent(email)+'/files');if(!res)return;const files=await res.json();if(!files.length){panel.innerHTML='<div style="color:var(--cf-text-subtle);font-size:12px;padding:4px 0">No files</div>';return;}panel.innerHTML=files.map(f=>{const isHtml=f.path.endsWith('.html');const viewUrl=BASE+'/view?user='+encodeURIComponent(email)+'&file='+encodeURIComponent(f.path);return\`<div class="file-row"><span class="file-path">\${f.path}</span><div style="display:flex;gap:8px;align-items:center">\${isHtml?'<a class="file-link" href="'+viewUrl+'" target="_blank">View ↗</a>':''}<button style="padding:3px 10px;font-size:11px" class="danger" onclick="deleteFile('\${email}','\${f.path}')">Delete</button></div></div>\`;}).join('');}else row.style.display='none';}
async function deleteFile(email,path){if(!confirm('Delete '+path+'?'))return;const res=await api('/users/'+encodeURIComponent(email)+'/files?path='+encodeURIComponent(path),{method:'DELETE'});if(res?.ok){toast('Deleted');const k=btoa(email).replace(/=/g,'');document.getElementById('files-'+k).style.display='none';toggleFiles(email);}else toast('Error',false);}
window.addEventListener('load',()=>{const s=sessionStorage.getItem('adminKey');if(s){document.getElementById('admin-key').value=s;authenticate();}});
document.getElementById('admin-key').addEventListener('keydown',e=>{if(e.key==='Enter')authenticate();});
</script>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}
