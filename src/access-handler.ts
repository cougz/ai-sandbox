import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { getSandbox } from "@cloudflare/sandbox";
import { Workspace } from "@cloudflare/shell";
import { proxyChatRequest } from "./chat-proxy";
import { handleChatAiProxy } from "./chat-ai-proxy";
import { AVAILABLE_MODELS, type ChatUserConfig } from "./chat-session";
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
import { buildBuiltinToolDefs } from "./tool-defs";
import { domainTools } from "./tools/example";

// ─── Types ────────────────────────────────────────────────────────────────────

type EnvWithOAuth = Env & { OAUTH_PROVIDER: OAuthHelpers };

interface UserRecord {
  email: string;
  name: string;
  createdAt: string;
}

type UserRole = "admin" | "user";

interface AuthenticatedUser {
  email: string;
  role: UserRole;
}

// ─── Built-in tool definitions ────────────────────────────────────────────────
// Single source of truth lives in ./tool-defs.ts.  Both agent.ts and this file
// derive their copies from the same function — no manual sync required.

const ADMIN_BUILTIN_TOOLS = buildBuiltinToolDefs(Object.keys(domainTools));

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
//   /dash                  ← unified dashboard (admin + user views)
//   /api/*                 ← dashboard REST API

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
    writeLog(env as Env, _ctx, "info", "auth.login", { email, name: claims.name ?? email, colo: (request.cf as Record<string, string> | undefined)?.colo });

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

  // ── WebSocket: interactive terminal for /dash ─────────────────────────────
  // The browser sends the __Host-DASH_SESSION cookie automatically; we
  // authenticate from that session before proxying to the container sandbox.
  if (pathname === "/dash/ws/terminal") {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("WebSocket upgrade required", { status: 426 });
    }
    const user = await authenticateRequest(request, env);
    if (!user) return new Response("Unauthorized", { status: 401 });
    // Per-user sandbox — stable ID derived from the authenticated email.
    const sandboxId = `dash-terminal-${emailToNamespace(user.email)}`;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sb = getSandbox((env as any).Sandbox, sandboxId) as any;
    return await sb.terminal(request, { cols: 220, rows: 50 });
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

  // ── Unified dashboard ─────────────────────────────────────────────────────
  if (pathname === "/dash") {
    const user = await authenticateRequest(request, env);
    if (!user) return new Response("Unauthorized", { status: 401 });
    // Issue a signed session cookie so that the dashboard's JavaScript fetch()
    // calls to /api/* can authenticate without CF Access headers.
    const sessionCookie = await createSessionCookie(user, env.COOKIE_ENCRYPTION_KEY);
    return serveDashboard(user, sessionCookie);
  }

  // ── Dashboard API ─────────────────────────────────────────────────────────
  if (pathname.startsWith("/api")) return handleApi(request, env, _ctx);

  // ── Workers AI proxy (/chat/ai/* — checked before auth) ─────────────────
  // Only reachable from the container (baseURL is set by ChatSession DO).
  // The container communicates via the Worker's own network, not the public internet.
  if (pathname.startsWith("/chat/ai/")) {
    const aiResp = await handleChatAiProxy(request, env.AI);
    if (aiResp) return aiResp;
  }

  // ── MCP OAuth callback (intentionally unauthenticated) ────────────────────
  if (pathname.startsWith("/chat/oauth/")) {
    const proxyResp = await proxyChatRequest(request, env);
    if (proxyResp) return proxyResp;
  }

  // ── Chat routes (all require session auth) ────────────────────────────────
  if (pathname === "/chat" || pathname.startsWith("/chat/")) {
    const user = await authenticateRequest(request, env);
    if (!user) return new Response("Unauthorized", { status: 401 });

    // Stable sandbox ID derived from the authenticated email
    const sandboxId = `chat-${emailToNamespace(user.email)}`;

    // Serve the embedded OpenCode web UI
    if (pathname === "/chat" || pathname === "/chat/") {
      // Validate the CF Access JWT audience for /chat on every initial page load
      // (the jwt-assertion header is only present on browser navigation, not on
      // subsequent fetch() calls which use the session cookie instead).
      const jwtAssertion = request.headers.get("cf-access-jwt-assertion");
      if (jwtAssertion && env.CHAT_AUD) {
        try {
          await verifyChatJwt(jwtAssertion, env.CHAT_AUD);
        } catch (err) {
          writeLog(env, _ctx, "warn", "chat.auth.aud_fail", {
            email: user.email,
            error: String(err),
          });
          return new Response("Forbidden", { status: 403 });
        }
      }
      const sessionCookie = await createSessionCookie(user, env.COOKIE_ENCRYPTION_KEY);
      // Kick off OpenCode startup — fire and forget.
      // ensureServer() returns immediately; ctx.waitUntil keeps the DO alive.
      // The chat page polls /chat/status/:sandboxId and mounts the UI when ready.
      const origin = new URL(request.url).origin;
      const chatSessionId = env.CHAT_SESSION.idFromName(user.email);
      const chatSession   = env.CHAT_SESSION.get(chatSessionId);
      (chatSession as unknown as { ensureServer(id: string, o: string): void })
        .ensureServer(sandboxId, origin);
      return serveChatPage(user, sandboxId, request, sessionCookie);
    }

    // OpenCode readiness check — polled by the loading screen
    if (pathname === `/chat/status/${sandboxId}`) {
      const chatSessionId = env.CHAT_SESSION.idFromName(user.email);
      const chatSession   = env.CHAT_SESSION.get(chatSessionId);
      const status = await (chatSession as unknown as { getStatus(id: string): string })
        .getStatus(sandboxId);
      return Response.json({ status });
    }

    // Proxy all /chat/oc/* to the OpenCode container
    if (pathname.startsWith("/chat/oc/")) {
      const proxyResp = await proxyChatRequest(request, env);
      if (proxyResp) return proxyResp;
    }

    // Chat configuration/status API
    if (pathname.startsWith("/chat/api/")) {
      return handleChatApi(request, new URL(request.url), env, user);
    }
  }

  return new Response("Not found", { status: 404 });
}

// ─── Authentication & Role Determination ──────────────────────────────────────

function getRole(email: string, env: Env): UserRole {
  if (!env.ADMIN_EMAILS) {
    console.log("[AUTH] ADMIN_EMAILS not configured, defaulting to user role");
    return "user";
  }
  const admins = env.ADMIN_EMAILS.toLowerCase().split(",").map((e) => e.trim());
  const isAdmin = admins.includes(email.toLowerCase());
  console.log(`[AUTH] Role check for ${email}: ${isAdmin ? "admin" : "user"} (admins: ${admins.join(", ")})`);
  return isAdmin ? "admin" : "user";
}

async function authenticateRequest(request: Request, env: Env): Promise<AuthenticatedUser | null> {
  // Primary path: Cloudflare Access injects these headers on the initial page load.
  const email        = request.headers.get("cf-access-authenticated-user-email");
  const jwtAssertion = request.headers.get("cf-access-jwt-assertion");

  console.log(`[AUTH] cf-access-authenticated-user-email: ${email}`);
  console.log(`[AUTH] cf-access-jwt-assertion present: ${!!jwtAssertion}`);

  if (email) {
    // We trust the header — Access validated the JWT at the edge before forwarding.
    if (jwtAssertion) console.log("[AUTH] JWT assertion present (verified by Cloudflare Access edge)");
    const role = getRole(email, env);
    console.log(`[AUTH] CF-Access header auth: ${email} (${role})`);
    return { email, role };
  }

  // Fallback path: JavaScript fetch() calls to /api/* don't carry CF Access headers.
  // Instead we accept a signed session cookie that was issued when /dash loaded.
  if (env.COOKIE_ENCRYPTION_KEY) {
    const sessionUser = await readSessionCookie(request, env.COOKIE_ENCRYPTION_KEY);
    if (sessionUser) {
      console.log(`[AUTH] Session cookie auth: ${sessionUser.email} (${sessionUser.role})`);
      return sessionUser;
    }
  }

  console.log("[AUTH] No CF-Access header and no valid session cookie — unauthenticated");
  return null;
}

// ─── Dashboard Session Cookie ─────────────────────────────────────────────────
// Issued when /dash loads successfully (CF Access header present).
// Carried automatically by the browser on every subsequent fetch() to /api/*,
// solving the reload loop caused by missing CF Access headers on XHR/fetch calls.

const SESSION_COOKIE = "__Host-DASH_SESSION";
const SESSION_TTL    = 8 * 60 * 60; // 8 hours

interface SessionPayload {
  email: string;
  role:  UserRole;
  exp:   number; // Unix timestamp
}

async function sessionHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
  );
}

async function createSessionCookie(user: AuthenticatedUser, secret: string): Promise<string> {
  const payload: SessionPayload = { email: user.email, role: user.role, exp: Math.floor(Date.now() / 1000) + SESSION_TTL };
  const payloadB64 = btoa(JSON.stringify(payload));
  const key        = await sessionHmacKey(secret);
  const raw        = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  const sig        = Array.from(new Uint8Array(raw)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `${SESSION_COOKIE}=${sig}.${payloadB64}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${SESSION_TTL}`;
}

async function readSessionCookie(request: Request, secret: string): Promise<AuthenticatedUser | null> {
  const cookieHeader = request.headers.get("Cookie") ?? "";
  const match        = cookieHeader.split(";").map(c => c.trim()).find(c => c.startsWith(`${SESSION_COOKIE}=`));
  if (!match) return null;

  const raw = match.slice(SESSION_COOKIE.length + 1);
  const dot = raw.indexOf(".");
  if (dot < 1) return null;

  const sig        = raw.slice(0, dot);
  const payloadB64 = raw.slice(dot + 1);

  const key   = await sessionHmacKey(secret);
  const bytes = new Uint8Array(sig.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  const valid = await crypto.subtle.verify("HMAC", key, bytes.buffer, new TextEncoder().encode(payloadB64));
  if (!valid) {
    console.log("[AUTH] Session cookie signature invalid");
    return null;
  }

  let payload: SessionPayload;
  try { payload = JSON.parse(atob(payloadB64)) as SessionPayload; }
  catch { return null; }

  if (payload.exp < Math.floor(Date.now() / 1000)) {
    console.log("[AUTH] Session cookie expired");
    return null;
  }
  return { email: payload.email, role: payload.role };
}

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
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
  const jwk = keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error(`No key found for kid=${kid}`);
  return crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

/**
 * Verify a CF Access self-hosted app JWT (cf-access-jwt-assertion header).
 *
 * Unlike verifyAccessToken() — which relies on ACCESS_JWKS_URL and is used
 * for the MCP OAuth flow — this function derives the JWKS URL directly from
 * the JWT's `iss` claim (always https://{team}.cloudflareaccess.com).
 * This means it works even when ACCESS_JWKS_URL is not configured.
 */
async function verifyChatJwt(token: string, expectedAud: string): Promise<void> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");

  const header  = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1])));

  // Derive JWKS URL from the issuer — always {team}.cloudflareaccess.com
  const issuer = typeof payload.iss === "string" ? payload.iss : null;
  if (!issuer) throw new Error("Missing iss claim in JWT");
  const jwksUrl = `${issuer}/cdn-cgi/access/certs`;

  const resp = await fetch(jwksUrl);
  if (!resp.ok) throw new Error(`Failed to fetch JWKS from ${jwksUrl}: ${resp.status}`);
  const { keys } = await resp.json<{ keys: (JsonWebKey & { kid: string })[] }>();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error(`No key found for kid=${header.kid}`);

  const key = await crypto.subtle.importKey(
    "jwk", jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false, ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key,
    fromBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) throw new Error("JWT signature invalid");
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error("JWT expired");

  const aud: string[] = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(expectedAud)) {
    throw new Error(`JWT audience mismatch (got: ${aud.join(", ")})`);
  }
}

/** Decode a base64url string to a Uint8Array (no Node.js Buffer required). */
function fromBase64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + (4 - s.length % 4) % 4, "=");
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function verifyAccessToken(
  env: Env,
  token: string,
  expectedAud?: string,
): Promise<Record<string, string>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");
  const header  = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1])));
  const key = await fetchAccessPublicKey(env, header.kid);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key,
    fromBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) throw new Error("JWT signature invalid");
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error("JWT expired");
  if (expectedAud) {
    // payload.aud can be a string or an array depending on the issuer
    const aud: string[] = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(expectedAud)) {
      throw new Error(`JWT audience mismatch (got: ${aud.join(", ")})`);
    }
  }
  return payload;
}

// ─── Observability ────────────────────────────────────────────────────────────
// Structured logging: writes to console (visible in Cloudflare Workers Observability
// and `wrangler tail`) AND stores a ring-buffer in KV for the admin panel.

type LogLevel = "info" | "warn" | "error";

interface LogEntry {
  ts:    string;
  level: LogLevel;
  event: string;
  data:  Record<string, unknown>;
}

const LOG_TTL  = 7 * 24 * 60 * 60; // 7 days
const LOG_KEY  = (ts: string) => `log:${ts}_${Math.random().toString(36).slice(2, 8)}`;

export function writeLog(
  env: Env,
  ctx: { waitUntil(p: Promise<unknown>): void },
  level: LogLevel,
  event: string,
  data: Record<string, unknown> = {},
): void {
  const entry: LogEntry = { ts: new Date().toISOString(), level, event, data };
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
  // Non-blocking KV write — TTL auto-expires entries after 7 days
  ctx.waitUntil(
    env.USER_REGISTRY.put(LOG_KEY(entry.ts), line, { expirationTtl: LOG_TTL })
  );
}

// ─── Dashboard API ────────────────────────────────────────────────────────────

async function handleApi(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const user = await authenticateRequest(request, env);
  if (!user) {
    writeLog(env, ctx, "warn", "api.auth.fail", { ip: request.headers.get("cf-connecting-ip") ?? "unknown" });
    return jsonResp({ error: "Unauthorized" }, 401);
  }

  const url    = new URL(request.url);
  const path   = url.pathname.replace(/^\/api/, "");
  const method = request.method.toUpperCase();

  // ── GET /navigation — return navigation items based on role ───────────────
  if (method === "GET" && path === "/navigation") {
    const items = user.role === "admin"
      ? [
          { id: "users", label: "Users" },
          { id: "tools", label: "Tools" },
          { id: "files", label: "Files" },
          { id: "logs", label: "Logs" },
          { id: "account", label: "My Account" },
        ]
      : [
          { id: "tools", label: "Tools" },
          { id: "files", label: "Files" },
          { id: "account", label: "My Account" },
        ];
    return jsonResp({ items });
  }

  // ── GET /me — current user info ───────────────────────────────────────────
  if (method === "GET" && path === "/me") {
    const record = await env.USER_REGISTRY.get<UserRecord>(`user:${user.email}`, "json");
    if (!record) return jsonResp({ error: "User not found" }, 404);
    
    let fileCount = 0;
    try {
      const entries = await makeWorkspace(user.email, env).glob("/**/*") as Array<{ type: string }>;
      fileCount = entries.filter((e) => e.type === "file").length;
    } catch { /* workspace may be empty */ }
    
    return jsonResp({ ...record, fileCount, role: user.role });
  }

  // ── GET /logs — fetch recent log entries from KV ring-buffer (admin only) ─
  if (method === "GET" && path === "/logs") {
    if (user.role !== "admin") {
      writeLog(env, ctx, "warn", "api.forbidden", { path, email: user.email });
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "200"), 500);
    const levelFilter = url.searchParams.get("level") ?? "all";
    try {
      const list = await env.USER_REGISTRY.list({ prefix: "log:", limit });
      const entries = await Promise.all(
        list.keys.map(async (k) => {
          const raw = await env.USER_REGISTRY.get(k.name);
          if (!raw) return null;
          try { return JSON.parse(raw) as LogEntry; } catch { return null; }
        })
      );
      let logs = entries.filter(Boolean) as LogEntry[];
      if (levelFilter !== "all") logs = logs.filter((l) => l.level === levelFilter);
      logs.sort((a, b) => b.ts.localeCompare(a.ts)); // newest first
      return jsonResp(logs);
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  // ── Global tools endpoints (shared workspace /tools/*.json) ──────────────────

  // GET /global-tools
  if (method === "GET" && path === "/global-tools") {
    try {
      const ws = makeSharedWorkspace(env);
      const entries = await ws.glob("/tools/*.json") as Array<{ path: string; type: string; size: number }>;
      const tools = await Promise.all(
        entries.filter((e) => e.type === "file").map(async (e) => {
          try {
            const content = await ws.readFile(e.path);
            if (!content) return { path: e.path, size: e.size };
            const def = JSON.parse(content);
            return { path: e.path, size: e.size, name: def.name, description: def.description };
          } catch { return { path: e.path, size: e.size }; }
        })
      );
      return jsonResp(tools);
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  // POST /global-tools (admin only)
  if (method === "POST" && path === "/global-tools") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    try {
      const body = await request.json<{ name?: string; description?: string; schema?: unknown; code?: string; path?: string; content?: string }>();
      let filePath: string;
      let fileContent: string;
      if (body.path && body.content !== undefined) {
        filePath    = body.path;
        fileContent = body.content;
      } else if (body.name && body.code) {
        filePath    = `/tools/${body.name}.json`;
        fileContent = JSON.stringify({ name: body.name, description: body.description ?? "", schema: body.schema ?? {}, code: body.code }, null, 2);
      } else {
        return jsonResp({ error: "Provide either {name, code} or {path, content}" }, 400);
      }
      const ws = makeSharedWorkspace(env);
      await ws.writeFile(filePath, fileContent);
      writeLog(env, ctx, "info", "admin.tools.upload", { path: filePath });
      return jsonResp({ uploaded: filePath });
    } catch (err) {
      writeLog(env, ctx, "error", "admin.tools.upload.error", { error: String(err) });
      return jsonResp({ error: String(err) }, 500);
    }
  }

  // DELETE /global-tools?name=... (admin only)
  if (method === "DELETE" && path === "/global-tools") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    const name = url.searchParams.get("name");
    if (!name) return jsonResp({ error: "Missing ?name=" }, 400);
    try {
      await makeSharedWorkspace(env).rm(`/tools/${name}.json`);
      writeLog(env, ctx, "info", "admin.tools.delete", { name });
      return jsonResp({ deleted: name });
    } catch (err) {
      writeLog(env, ctx, "error", "admin.tools.delete.error", { name, error: String(err) });
      return jsonResp({ error: String(err) }, 500);
    }
  }

  // ── Shared workspace endpoints ─────────────────────────────────────────────

  if (method === "GET" && path === "/shared/files") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    try {
      const entries = await makeSharedWorkspace(env).glob("/**/*") as Array<{ path: string; type: string; size: number; updatedAt: number }>;
      return jsonResp(entries.filter((e) => e.type === "file").map((e) => ({ path: e.path, size: e.size, updatedAt: e.updatedAt })));
    } catch (err) { return jsonResp({ error: String(err) }, 500); }
  }

  if (method === "POST" && path === "/shared/files") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    try {
      const body = await request.json<{ path: string; content: string }>();
      if (!body.path)              return jsonResp({ error: "path is required" }, 400);
      if (body.content === undefined) return jsonResp({ error: "content is required" }, 400);
      await makeSharedWorkspace(env).writeFile(body.path, body.content);
      writeLog(env, ctx, "info", "admin.shared.write", { path: body.path, bytes: body.content.length });
      return jsonResp({ uploaded: body.path });
    } catch (err) {
      writeLog(env, ctx, "error", "admin.shared.write.error", { error: String(err) });
      return jsonResp({ error: String(err) }, 500);
    }
  }

  if (method === "DELETE" && path === "/shared/files") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    const filePath = url.searchParams.get("path");
    if (!filePath) return jsonResp({ error: "Missing ?path=" }, 400);
    try {
      await makeSharedWorkspace(env).rm(filePath);
      writeLog(env, ctx, "info", "admin.shared.delete", { path: filePath });
      return jsonResp({ deleted: filePath });
    } catch (err) {
      writeLog(env, ctx, "error", "admin.shared.delete.error", { path: filePath, error: String(err) });
      return jsonResp({ error: String(err) }, 500);
    }
  }

  // ── User endpoints ─────────────────────────────────────────────────────────

  if (method === "GET" && path === "/users") {
    if (user.role === "admin") {
      // Admin: return all users
      const list = await env.USER_REGISTRY.list({ prefix: "user:" });
      const users = await Promise.all(list.keys.map(async (k) => {
        const r = await env.USER_REGISTRY.get<UserRecord>(k.name, "json");
        if (!r) return null;
        let fileCount = 0;
        try {
          const entries = await makeWorkspace(r.email, env).glob("/**/*") as Array<{ type: string }>;
          fileCount = entries.filter((e) => e.type === "file").length;
        } catch { /* workspace may be empty */ }
        return { ...r, fileCount };
      }));
      return jsonResp(users.filter(Boolean));
    } else {
      // Non-admin: return current user only
      const record = await env.USER_REGISTRY.get<UserRecord>(`user:${user.email}`, "json");
      if (!record) return jsonResp({ error: "User not found" }, 404);
      
      let fileCount = 0;
      try {
        const entries = await makeWorkspace(user.email, env).glob("/**/*") as Array<{ type: string }>;
        fileCount = entries.filter((e) => e.type === "file").length;
      } catch { /* workspace may be empty */ }
      
      return jsonResp([{ ...record, fileCount }]); // Return as array for consistent frontend
    }
  }

  if (method === "POST" && path === "/users") {
    if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
    
    const body = await request.json<{ name?: string; email: string }>();
    if (!body.email) return jsonResp({ error: "email is required" }, 400);
    await ensureUserRecord(body.email, body.name ?? body.email, env);
    writeLog(env, ctx, "info", "admin.users.provision", { email: body.email });
    return jsonResp({ email: body.email, name: body.name ?? body.email }, 201);
  }

  const userMatch = path.match(/^\/users\/([^/]+)(\/.*)?$/);
  if (userMatch) {
    const email = decodeURIComponent(userMatch[1]);
    const sub   = userMatch[2] ?? "";
    
    // Non-admins can only access their own user record
    if (user.role !== "admin" && email !== user.email) {
      return jsonResp({ error: "Forbidden" }, 403);
    }

    if (method === "DELETE" && sub === "") {
      if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
      
      await env.USER_REGISTRY.delete(`user:${email}`);
      writeLog(env, ctx, "info", "admin.users.remove", { email });
      return jsonResp({ deleted: email });
    }

    const workspace = makeWorkspace(email, env);

    if (method === "GET" && sub === "/files") {
      try {
        const entries = await workspace.glob("/**/*") as Array<{ path: string; type: string; size: number; updatedAt: number }>;
        return jsonResp(entries.filter((e) => e.type === "file").map((e) => ({ path: e.path, size: e.size, updatedAt: e.updatedAt })));
      } catch (err) { return jsonResp({ error: String(err) }, 500); }
    }

    if (method === "DELETE" && sub === "/workspace") {
      if (user.role !== "admin") return jsonResp({ error: "Forbidden" }, 403);
      
      try {
        const entries = await workspace.glob("/**/*") as Array<{ path: string; type: string }>;
        await Promise.all(entries.filter((e) => e.type === "file").map((e) => workspace.rm(e.path)));
        writeLog(env, ctx, "info", "admin.workspace.wipe", { email, files: entries.length });
      } catch { /* already empty */ }
      return jsonResp({ wiped: email });
    }

    if (method === "DELETE" && sub === "/files") {
      const filePath = url.searchParams.get("path");
      if (!filePath) return jsonResp({ error: "Missing ?path=" }, 400);
      await workspace.rm(filePath);
      writeLog(env, ctx, "info", "admin.files.delete", { email, path: filePath });
      return jsonResp({ deleted: filePath });
    }
  }

  // ── GET /tools — list all tools (built-in static + custom from shared ws) ──
  // Scans /tools/{name}/tool.json (directory format, new standard) and
  // /tools/{name}.json (flat format, backward compat). Directory takes precedence.
  if (method === "GET" && path === "/tools") {
    const ws = makeSharedWorkspace(env);
    let customTools: unknown[] = [];
    try {
      const entries = await ws.glob("/tools/**") as Array<{ path: string; type: string }>;
      const dir  = entries.filter((e) => e.type === "file" && /^\/tools\/[^/]+\/tool\.json$/.test(e.path));
      const flat = entries.filter((e) => e.type === "file" && /^\/tools\/[^/]+\.json$/.test(e.path));
      const seen = new Set<string>();
      const loaded: unknown[] = [];
      for (const entry of [...dir, ...flat]) {
        const m = entry.path.match(/^\/tools\/([^/]+)(?:\/tool)?\.json$/);
        if (!m || seen.has(m[1])) continue;
        const raw = await ws.readFile(entry.path);
        if (!raw) continue;
        try {
          const def = JSON.parse(raw);
          // Add actions based on role
          (def as Record<string, unknown>).actions = user.role === "admin" 
            ? ["view", "edit", "delete"] 
            : ["view"];
          // For directory tools, list supporting files
          if (/^\/tools\/[^/]+\/tool\.json$/.test(entry.path)) {
            const toolDir = entry.path.replace("/tool.json", "");
            (def as Record<string, unknown>)._files = entries
              .filter((e) => e.type === "file" && e.path.startsWith(toolDir + "/") && e.path !== entry.path)
              .map((e) => e.path);
          }
          loaded.push(def);
          seen.add(m[1]);
        } catch { /* skip malformed */ }
      }
      customTools = loaded;
    } catch { /* shared workspace empty or unavailable */ }
    writeLog(env, ctx, "info", "admin.tools.list", { builtin: ADMIN_BUILTIN_TOOLS.length, custom: customTools.length });
    return jsonResp({ builtin: ADMIN_BUILTIN_TOOLS, custom: customTools });
  }

  // ── Unified file-browser endpoints ─────────────────────────────────────────

  if (method === "GET" && path === "/files") {
    const wsName = url.searchParams.get("workspace");
    if (!wsName) return jsonResp({ error: "Missing ?workspace=" }, 400);
    
    // Non-admins can only access their own workspace
    if (user.role !== "admin" && wsName !== user.email && wsName !== "shared") {
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const ws = wsName === "shared" ? makeSharedWorkspace(env) : makeWorkspace(wsName, env);
    try {
      const entries = await ws.glob("/**/*") as Array<{ path: string; type: string; size: number; updatedAt: number }>;
      return jsonResp(entries.filter((e) => e.type === "file").map((e) => ({ path: e.path, size: e.size, updatedAt: e.updatedAt })));
    } catch { return jsonResp([]); }
  }

  if (method === "GET" && path === "/files/read") {
    const wsName   = url.searchParams.get("workspace");
    const filePath = url.searchParams.get("path");
    if (!wsName || !filePath) return jsonResp({ error: "Missing params" }, 400);
    
    // Non-admins can only access their own workspace
    if (user.role !== "admin" && wsName !== user.email && wsName !== "shared") {
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const content = await (wsName === "shared" ? makeSharedWorkspace(env) : makeWorkspace(wsName, env)).readFile(filePath);
    if (content === null) return jsonResp({ error: "File not found" }, 404);
    return new Response(content, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
  }

  if (method === "POST" && path === "/files/write") {
    const wsName   = url.searchParams.get("workspace");
    const filePath = url.searchParams.get("path");
    if (!wsName || !filePath) return jsonResp({ error: "Missing params" }, 400);
    
    // Non-admins can only access their own workspace
    if (user.role !== "admin" && wsName !== user.email && wsName !== "shared") {
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const content = await request.text();
    const ws = wsName === "shared" ? makeSharedWorkspace(env) : makeWorkspace(wsName, env);
    await ws.writeFile(filePath, content);
    writeLog(env, ctx, "info", "admin.files.write", { workspace: wsName, path: filePath, bytes: content.length });
    return jsonResp({ written: filePath });
  }

  if (method === "POST" && path === "/files/mkdir") {
    const wsName  = url.searchParams.get("workspace");
    const dirPath = url.searchParams.get("path");
    if (!wsName || !dirPath) return jsonResp({ error: "Missing params" }, 400);
    
    // Non-admins can only access their own workspace
    if (user.role !== "admin" && wsName !== user.email && wsName !== "shared") {
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const ws = wsName === "shared" ? makeSharedWorkspace(env) : makeWorkspace(wsName, env);
    await ws.writeFile(dirPath.replace(/\/*$/, "") + "/.keep", "");
    writeLog(env, ctx, "info", "admin.files.mkdir", { workspace: wsName, path: dirPath });
    return jsonResp({ created: dirPath });
  }

  if (method === "DELETE" && path === "/files") {
    const wsName   = url.searchParams.get("workspace");
    const filePath = url.searchParams.get("path");
    if (!wsName || !filePath) return jsonResp({ error: "Missing params" }, 400);
    
    // Non-admins can only access their own workspace
    if (user.role !== "admin" && wsName !== user.email && wsName !== "shared") {
      return jsonResp({ error: "Forbidden" }, 403);
    }
    
    const ws = wsName === "shared" ? makeSharedWorkspace(env) : makeWorkspace(wsName, env);
    try {
      await ws.rm(filePath);
      writeLog(env, ctx, "info", "admin.files.delete", { workspace: wsName, path: filePath });
    } catch (err) {
      writeLog(env, ctx, "error", "admin.files.delete.error", { workspace: wsName, path: filePath, error: String(err) });
      return jsonResp({ error: String(err) }, 500);
    }
    return jsonResp({ deleted: filePath });
  }

  writeLog(env, ctx, "warn", "admin.api.not_found", { method, path });
  return jsonResp({ error: "Not found" }, 404 );
}

// ─── Dashboard HTML ───────────────────────────────────────────────────────────

function serveDashboard(user: AuthenticatedUser, sessionCookie: string): Response {
  const isAdmin = user.role === "admin";
  
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Sandbox — Dashboard</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NiA2NiI+PHJlY3Qgd2lkdGg9IjY2IiBoZWlnaHQ9IjY2IiByeD0iOSIgZmlsbD0iI0ZGNDgwMSIvPjxnIHRyYW5zZm9ybT0idHJhbnNsYXRlKDAsMTgpIiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTUyLjY4OCAxMy4wMjhjLS4yMiAwLS40MzcuMDA4LS42NTQuMDE1YS4zLjMgMCAwIDAtLjEwMi4wMjQuMzcuMzcgMCAwIDAtLjIzNi4yNTVsLS45MyAzLjI0OWMtLjQwMSAxLjM5Ny0uMjUyIDIuNjg3LjQyMiAzLjYzNC42MTguODc2IDEuNjQ2IDEuMzkgMi44OTQgMS40NWw1LjA0NS4zMDZhLjQ1LjQ1IDAgMCAxIC40MzUuNDEuNS41IDAgMCAxLS4wMjUuMjIzLjY0LjY0IDAgMCAxLS41NDcuNDI2bC01LjI0Mi4zMDZjLTIuODQ4LjEzMi01LjkxMiAyLjQ1Ni02Ljk4NyA1LjI5bC0uMzc4IDFhLjI4LjI4IDAgMCAwIC4yNDguMzgyaDE4LjA1NGEuNDguNDggMCAwIDAgLjQ2NC0uMzVjLjMyLTEuMTUzLjQ4Mi0yLjM0NC40OC0zLjU0IDAtNy4yMi01Ljc5LTEzLjA3Mi0xMi45MzMtMTMuMDcyTTQ0LjgwNyAyOS41NzhsLjMzNC0xLjE3NWMuNDAyLTEuMzk3LjI1My0yLjY4Ny0uNDItMy42MzQtLjYyLS44NzYtMS42NDctMS4zOS0yLjg5Ni0xLjQ1bC0yMy42NjUtLjMwNmEuNDcuNDcgMCAwIDEtLjM3NC0uMTk5LjUuNSAwIDAgMS0uMDUyLS40MzQuNjQuNjQgMCAwIDEgLjU1Mi0uNDI2bDIzLjg4Ni0uMzA2YzIuODM2LS4xMzEgNS45LTIuNDU2IDYuOTc1LTUuMjlsMS4zNjItMy42YS45LjkgMCAwIDAgLjA0LS40NzdDNDguOTk3IDUuMjU5IDQyLjc4OSAwIDM1LjM2NyAwYy02Ljg0MiAwLTEyLjY0NyA0LjQ2Mi0xNC43MyAxMC42NjVhNi45MiA2LjkyIDAgMCAwLTQuOTExLTEuMzc0Yy0zLjI4LjMzLTUuOTIgMy4wMDItNi4yNDYgNi4zMThhNy4yIDcuMiAwIDAgMCAuMTggMi40NzJDNC4zIDE4LjI0MSAwIDIyLjY3OSAwIDI4LjEzM3EwIC43NC4xMDYgMS40NTNhLjQ2LjQ2IDAgMCAwIC40NTcuNDAyaDQzLjcwNGEuNTcuNTcgMCAwIDAgLjU0LS40MTgiLz48L2c+PC9zdmc+">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5/css/xterm.css">
<style>
html{color-scheme:light}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--cf-orange:#FF4801;--cf-text:#521000;--cf-text-muted:rgba(82,16,0,.7);--cf-text-subtle:rgba(82,16,0,.4);--cf-bg:#FFFBF5;--cf-bg-card:#FFFDFB;--cf-bg-hover:#FEF7ED;--cf-border:#EBD5C1;--cf-success:#16A34A;--cf-error:#DC2626}
html,body{height:100%;overflow:hidden}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--cf-bg);color:var(--cf-text);line-height:1.5;-webkit-font-smoothing:antialiased}
#app{height:100vh}
.shell{display:flex;height:100vh}
#sidebar{width:220px;min-width:220px;height:100vh;border-right:1px solid var(--cf-border);display:flex;flex-direction:column;background:var(--cf-bg)}
.logo-area{padding:18px 16px 14px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--cf-border)}
.logo-svg{color:var(--cf-orange);height:26px;flex-shrink:0}
.logo-eyebrow{font-size:9px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--cf-text-muted);line-height:1.2}
.logo-name{font-size:15px;font-weight:500;color:var(--cf-text);letter-spacing:-.02em;line-height:1.2}
nav{flex:1;padding:8px 0}
.nav-item{display:flex;align-items:center;gap:9px;padding:9px 16px;cursor:pointer;font-size:13px;color:var(--cf-text-muted);border-left:2px solid transparent;transition:all .1s;user-select:none}
.nav-item:hover{color:var(--cf-text);background:var(--cf-bg-hover)}
.nav-item.active{color:var(--cf-orange);border-left-color:var(--cf-orange);background:rgba(255,72,1,.05);font-weight:500}
.nav-ico{width:14px;height:14px;flex-shrink:0}
.nav-num{font-size:9px;font-variant-numeric:tabular-nums;letter-spacing:.06em;color:var(--cf-text-subtle);min-width:16px;flex-shrink:0;line-height:1}
#main{flex:1;overflow-y:auto;height:100vh}
.section{display:none;padding:36px 44px;max-width:1140px}
.section.active{display:block}
.sec-title{font-size:24px;font-weight:500;letter-spacing:-.02em;margin-bottom:4px}
.sec-sub{font-size:13px;color:var(--cf-text-muted);margin-bottom:26px}
.card{background:var(--cf-bg-card);border:1px solid var(--cf-border);margin-bottom:18px}
.card-hdr{padding:11px 16px;border-bottom:1px solid rgba(235,213,193,.4);display:flex;align-items:center;justify-content:space-between}
.card-hdr-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted)}
.card-body{padding:16px}
.form-row{display:flex;gap:8px;align-items:flex-end}
.form-field{flex:1}
label{display:block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:4px}
input,select,textarea{border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text);font-family:inherit;font-size:13px;border-radius:4px;padding:7px 10px;width:100%;outline:none;transition:border-color .15s}
input:focus,select:focus,textarea:focus{border-color:var(--cf-orange)}
textarea{resize:vertical;font-family:"SF Mono","Fira Code",monospace;font-size:12px;line-height:1.5}
button{display:inline-flex;align-items:center;gap:5px;padding:6px 13px;border-radius:9999px;font-size:12px;font-weight:500;border:1px solid var(--cf-border);background:var(--cf-bg-card);color:var(--cf-text-muted);cursor:pointer;transition:all .12s;font-family:inherit;line-height:1.4;white-space:nowrap}
button:hover{background:var(--cf-bg-hover);color:var(--cf-text)}
button.primary{background:var(--cf-orange);color:#fff;border-color:transparent}
button.primary:hover{opacity:.9}
button.danger{color:var(--cf-error);border-color:rgba(220,38,38,.3)}
button.danger:hover{background:rgba(220,38,38,.06)}
button.sm{padding:3px 9px;font-size:11px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:7px 12px;text-align:left;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--cf-text-muted);border-bottom:1px solid var(--cf-border);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid rgba(235,213,193,.25);vertical-align:middle;color:var(--cf-text-muted)}
td strong{color:var(--cf-text);font-weight:500}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--cf-bg-hover)}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;font-size:10px;font-weight:600}
.badge-g{background:rgba(22,163,74,.1);color:var(--cf-success)}
.badge-m{background:rgba(235,213,193,.4);color:var(--cf-text-muted)}
.empty{padding:28px;text-align:center;color:var(--cf-text-subtle);font-size:13px}
.tools-group{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--cf-text-muted);padding-bottom:8px;border-bottom:1px solid var(--cf-border);margin-bottom:12px;margin-top:24px}
.tools-group:first-child{margin-top:0}
.tool-card{border:1px solid var(--cf-border);background:var(--cf-bg-card);padding:14px 16px;margin-bottom:8px}
.tool-card-hdr{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}
.tool-name{font-family:"SF Mono","Fira Code",monospace;font-size:13px;font-weight:600;color:var(--cf-text);background:rgba(255,72,1,.06);padding:2px 8px;border-radius:4px;border:1px solid rgba(255,72,1,.15)}
.tool-desc{font-size:12px;color:var(--cf-text-muted);line-height:1.55;white-space:pre-line;margin-bottom:6px}
.params-tbl{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;display:none}
.params-tbl th{padding:4px 8px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--cf-text-subtle);border-bottom:1px solid var(--cf-border);text-align:left}
.params-tbl td{padding:5px 8px;border-bottom:1px solid rgba(235,213,193,.2);color:var(--cf-text-muted);vertical-align:top}
.params-tbl tr:last-child td{border-bottom:none}
.params-tbl code{font-family:"SF Mono","Fira Code",monospace;font-size:11px;background:rgba(235,213,193,.35);padding:1px 4px;border-radius:3px}
.ws-bar{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.ws-bar label{margin:0;white-space:nowrap}
.file-browser{display:flex;flex-direction:column;gap:16px}
.fb-left{border:1px solid var(--cf-border);background:var(--cf-bg-card);display:flex;flex-direction:column}
.fb-hdr{display:flex;align-items:center;justify-content:space-between;padding:9px 13px;border-bottom:1px solid rgba(235,213,193,.4)}
.fb-path{font-family:"SF Mono","Fira Code",monospace;font-size:12px;color:var(--cf-text);font-weight:500}
.fb-count{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted)}
#file-tree{overflow-y:auto;height:460px}
.tree-row{display:flex;align-items:center;gap:8px;padding:8px 13px;border-bottom:1px solid rgba(235,213,193,.18);font-size:13px;cursor:pointer;transition:background .08s;position:relative}
.tree-row:last-child{border-bottom:none}
.tree-row:hover{background:var(--cf-bg-hover)}
.tree-row.selected{background:rgba(255,72,1,.06)}
.tree-name{flex:1;font-family:"SF Mono","Fira Code",monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tree-size{font-size:10px;color:var(--cf-text-subtle);white-space:nowrap;margin-left:4px}
.tree-del{background:none;border:none;color:var(--cf-error);padding:1px 6px;opacity:0;cursor:pointer;font-size:15px;line-height:1;border-radius:3px;flex-shrink:0}
.tree-row:hover .tree-del{opacity:.7}
.tree-del:hover{opacity:1!important;background:rgba(220,38,38,.08)}
.tree-url{background:none;border:none;color:var(--cf-text-subtle);padding:1px 4px;opacity:0;cursor:pointer;font-size:13px;line-height:1;border-radius:3px;flex-shrink:0;text-decoration:none;display:inline-flex;align-items:center}
.tree-row:hover .tree-url{opacity:.6}
.tree-url:hover{opacity:1!important;color:var(--cf-orange)!important;background:rgba(255,72,1,.08)}
.tree-date{font-size:10px;color:var(--cf-text-subtle);white-space:nowrap;margin-left:4px;font-variant-numeric:tabular-nums;flex-shrink:0}
.tree-dl{background:none;border:none;color:var(--cf-text-subtle);padding:1px 5px;opacity:0;cursor:pointer;font-size:12px;line-height:1;border-radius:3px;flex-shrink:0}
.tree-row:hover .tree-dl{opacity:.6}
.tree-dl:hover{opacity:1!important;color:var(--cf-orange)!important;background:rgba(255,72,1,.08)}
.fb-action{background:var(--cf-bg-card);border:1px solid var(--cf-border);padding:14px 15px}
.viewer-lbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:5px}
.viewer-filepath{font-family:"SF Mono","Fira Code",monospace;font-size:11px;color:var(--cf-text-subtle);margin-bottom:6px;min-height:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-viewer{background:#1C0A00;color:#f5e6d3;font-family:"SF Mono","Fira Code",monospace;font-size:12px;line-height:1.5;padding:13px 14px;min-height:160px;max-height:320px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;border:1px solid #3a1500}
.toast{position:fixed;bottom:18px;right:20px;background:var(--cf-text);color:var(--cf-bg);padding:8px 16px;border-radius:9999px;font-size:12px;font-weight:500;opacity:0;transition:opacity .2s;pointer-events:none;z-index:500}
.toast.show{opacity:1}
.file-editor-ta{background:#1C0A00;color:#f5e6d3;font-family:"SF Mono","Fira Code",monospace;font-size:12px;line-height:1.5;padding:13px 14px;min-height:540px;max-height:80vh;overflow-y:auto;resize:vertical;width:100%;outline:none;border:1px solid #3a1500;display:block;border-radius:0}
.file-editor-ta:focus{border-color:var(--cf-orange)}
.account-info{display:grid;grid-template-columns:200px 1fr;gap:16px;margin-bottom:24px}
.account-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted)}
.account-value{font-size:14px;color:var(--cf-text)}
</style>
</head>
<body>
<div id="app"><div class="shell">
  <aside id="sidebar">
    <div class="logo-area">
      <svg class="logo-svg" viewBox="0 0 66 30" fill="currentColor"><path d="M52.688 13.028c-.22 0-.437.008-.654.015a.3.3 0 0 0-.102.024.37.37 0 0 0-.236.255l-.93 3.249c-.401 1.397-.252 2.687.422 3.634.618.876 1.646 1.39 2.894 1.45l5.045.306a.45.45 0 0 1 .435.41.5.5 0 0 1-.025.223.64.64 0 0 1-.547.426l-5.242.306c-2.848.132-5.912 2.456-6.987 5.29l-.378 1a.28.28 0 0 0 .248.382h18.054a.48.48 0 0 0 .464-.35c.32-1.153.482-2.344.48-3.54 0-7.22-5.79-13.072-12.933-13.072M44.807 29.578l.334-1.175c.402-1.397.253-2.687-.42-3.634-.62-.876-1.647-1.39-2.896-1.45l-23.665-.306a.47.47 0 0 1-.374-.199.5.5 0 0 1-.052-.434.64.64 0 0 1 .552-.426l23.886-.306c2.836-.131 5.9-2.456 6.975-5.29l1.362-3.6a.9.9 0 0 0 .04-.477C48.997 5.259 42.789 0 35.367 0c-6.842 0-12.647 4.462-14.73 10.665a6.92 6.92 0 0 0-4.911-1.374c-3.28.33-5.92 3.002-6.246 6.318a7.2 7.2 0 0 0 .18 2.472C4.3 18.241 0 22.679 0 28.133q0 .74.106 1.453a.46.46 0 0 0 .457.402h43.704a.57.57 0 0 0 .54-.418"/></svg>
      <div><div class="logo-eyebrow">Cloudflare</div><div class="logo-name">Sandbox</div></div>
    </div>
    <nav id="nav">
      <!-- Navigation items will be loaded dynamically -->
    </nav>
  </aside>
  <main id="main">
    <div id="sec-users" class="section">
      <div class="sec-title">Users</div>
      <div class="sec-sub">Users appear automatically after their first Access login. Workspaces are persistent across sessions.</div>
      <div class="card">
        <div class="card-hdr"><span class="card-hdr-label">Provision User</span></div>
        <div class="card-body">
          <div class="form-row" style="gap:10px">
            <div class="form-field"><label>Display Name</label><input id="new-name" placeholder="Jane Doe"></div>
            <div class="form-field"><label>Email</label><input id="new-email" placeholder="jane@cloudflare.com"></div>
            <button class="primary" id="add-user-btn" style="margin-top:18px">Add</button>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-hdr">
          <span class="card-hdr-label">Users</span>
          <div style="display:flex;gap:8px;align-items:center">
            <span id="user-count" class="badge badge-m">&mdash;</span>
            <button id="refresh-btn" class="sm">&#8635; Refresh</button>
          </div>
        </div>
        <div id="users-body"><div class="empty">Loading&hellip;</div></div>
      </div>
    </div>
    <div id="sec-tools" class="section">
      <div class="sec-title">Global Tools</div>
      <div class="sec-sub">All tools available in the AI Sandbox &mdash; built-in and custom tools from the Shared Workspace (<code style="font-size:11px;font-family:monospace;background:rgba(235,213,193,.4);padding:1px 5px;border-radius:3px">/tools/*.json</code>). Custom tools load for every user at session start.</div>
      <div id="tools-body"><div class="empty">Loading&hellip;</div></div>
    </div>
    <div id="sec-files" class="section">
      <div class="sec-title">File Manager</div>
      <div class="sec-sub">Browse and manage files across personal and shared workspaces.</div>
      <div class="ws-bar">
        <label style="min-width:80px">Workspace</label>
        <select id="ws-sel" style="max-width:320px"><option value="shared">Shared Workspace</option></select>
      </div>
      <div class="file-browser">
        <div class="fb-left">
          <div class="fb-hdr">
            <span class="fb-path" id="fb-path">/</span>
            <span class="fb-count" id="fb-count">&mdash;</span>
          </div>
          <div id="file-tree"><div class="empty">Select a workspace and click Load Files.</div></div>
        </div>
        <div class="fb-action">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
            <div class="viewer-lbl">File Editor</div>
            <button class="sm primary" id="save-file-btn" style="display:none">Save</button>
          </div>
          <div class="viewer-filepath" id="viewer-path">Select a file to view its contents</div>
          <textarea class="file-editor-ta" id="file-editor" placeholder="Select a file to edit its contents." readonly></textarea>
        </div>
      </div>
    </div>

    <div id="sec-logs" class="section">
      <div class="sec-title">Logs</div>
      <div class="sec-sub">Structured Worker events stored in KV (7-day TTL). All entries also appear in <strong>Cloudflare Workers Observability</strong> and <code style="font-family:monospace;font-size:11px;background:rgba(235,213,193,.4);padding:1px 5px;border-radius:3px">wrangler tail</code>.</div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
        <div id="log-filter" style="display:flex;gap:6px">
          <button class="sm active-filter" data-lvl="all">All</button>
          <button class="sm" data-lvl="error" style="color:var(--cf-error);border-color:rgba(220,38,38,.3)">Errors</button>
          <button class="sm" data-lvl="warn"  style="color:#b45309;border-color:rgba(180,83,9,.3)">Warnings</button>
          <button class="sm" data-lvl="info">Info</button>
        </div>
        <button class="sm primary" id="refresh-logs-btn">&#8635; Refresh</button>
        <span id="log-count" style="font-size:11px;color:var(--cf-text-muted);margin-left:auto"></span>
      </div>
      <div class="card" style="overflow:hidden">
        <div id="logs-body"><div class="empty">Loading&hellip;</div></div>
      </div>
    </div>

    <div id="sec-terminal" class="section">
      <div class="sec-title">Interactive Terminal</div>
      <div class="sec-sub">Full interactive terminal session connected to a dedicated sandbox container via WebSocket. Supports tab completion, history, colors, and all PTY features.</div>
      <div style="background:#160a00;border:1px solid var(--cf-border);border-radius:4px;padding:4px;position:relative">
        <div id="terminal-connecting" style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;background:rgba(22,10,0,.94);z-index:10;border-radius:4px">
          <div style="display:flex;align-items:flex-end;gap:3px;height:24px">
            <div class="sig-bar" style="--d:0;width:3px;border-radius:2px;background:var(--cf-orange)"></div>
            <div class="sig-bar" style="--d:1;width:3px;border-radius:2px;background:var(--cf-orange)"></div>
            <div class="sig-bar" style="--d:2;width:3px;border-radius:2px;background:var(--cf-orange)"></div>
            <div class="sig-bar" style="--d:3;width:3px;border-radius:2px;background:var(--cf-orange)"></div>
            <div class="sig-bar" style="--d:4;width:3px;border-radius:2px;background:var(--cf-orange)"></div>
          </div>
          <span style="font-size:13px;font-weight:500;color:rgba(245,230,211,.7)">Connecting to sandbox&hellip;</span>
        </div>
        <div id="xterm-mount" style="height:440px"></div>
      </div>
      <div id="term-cmds" style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px"></div>
    </div>

    <div id="sec-account" class="section">
      <div class="sec-title">My Account</div>
      <div class="sec-sub">Your workspace and account information.</div>
      <div class="card">
        <div class="card-hdr"><span class="card-hdr-label">Account Details</span></div>
        <div class="card-body">
          <div class="account-info">
            <div class="account-label">Email</div>
            <div class="account-value" id="account-email">Loading&hellip;</div>
            <div class="account-label">Name</div>
            <div class="account-value" id="account-name">Loading&hellip;</div>
            <div class="account-label">First Login</div>
            <div class="account-value" id="account-created">Loading&hellip;</div>
            <div class="account-label">Workspace Files</div>
            <div class="account-value" id="account-files">Loading&hellip;</div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div></div>
<div class="toast" id="toast"></div>
<script>
// User configuration injected by server
const USER_EMAIL = ${JSON.stringify(user.email)};
const IS_ADMIN = ${JSON.stringify(isAdmin)};

var BASE=window.location.origin,bWs='shared',bPath='/',bFiles=[],pendingEditFile=null,currentEditPath='';
var logLevel='all',logTimer=null;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(msg,ok){var el=document.getElementById('toast');el.textContent=msg;el.style.background=(ok===false)?'var(--cf-error)':'var(--cf-text)';el.classList.add('show');setTimeout(function(){el.classList.remove('show');},2500);}

// API calls - cookie is sent automatically by browser
async function api(path,opts){opts=opts||{};var res=await fetch(BASE+'/api'+path,Object.assign({credentials:'include'},opts));if(res.status===401){window.location.reload();return null;}if(res.status===403){toast('Access denied',false);return null;}return res;}

// Navigation
// Icon SVG inner-content strings — multi-element, 16×16 viewBox, round caps/joins
var ICONS={
  users:'<circle cx="5.5" cy="5" r="2.5"/><path d="M1 14c0-2.5 2-4.5 4.5-4.5s4.5 2 4.5 4.5"/><circle cx="11.5" cy="5" r="2"/><path d="M14.5 14c0-2-1.5-3.5-3-3.5"/>',
  tools:'<path d="M2 4h12M2 8h12M2 12h12"/><circle cx="5" cy="4" r="1.5"/><circle cx="11" cy="8" r="1.5"/><circle cx="7" cy="12" r="1.5"/>',
  files:'<path d="M1.5 5A1.5 1.5 0 013 3.5h4L8.5 5H13A1.5 1.5 0 0114.5 6.5v6A1.5 1.5 0 0113 14H3a1.5 1.5 0 01-1.5-1.5z"/>',
  logs:'<rect x="2.5" y="1.5" width="11" height="13" rx="1.5"/><path d="M5 5.5h6M5 8h6M5 10.5h3.5"/>',
  terminal:'<polyline points="3 6 7 10 3 14"/><line x1="9" y1="14" x2="14" y2="14"/>',
  account:'<circle cx="8" cy="5.5" r="2.5"/><path d="M3 14c0-2.8 2.2-5 5-5s5 2.2 5 5"/>'
};
var navItems=IS_ADMIN?[
  {id:'users',label:'Users',svg:ICONS.users},
  {id:'tools',label:'Tools',svg:ICONS.tools},
  {id:'files',label:'Files',svg:ICONS.files},
  {id:'logs',label:'Logs',svg:ICONS.logs},
  {id:'terminal',label:'Terminal',svg:ICONS.terminal},
  {id:'account',label:'My Account',svg:ICONS.account}
]:[
  {id:'tools',label:'Tools',svg:ICONS.tools},
  {id:'files',label:'Files',svg:ICONS.files},
  {id:'terminal',label:'Terminal',svg:ICONS.terminal},
  {id:'account',label:'My Account',svg:ICONS.account}
];

function buildNav(){
  var nav=document.getElementById('nav');nav.innerHTML='';
  navItems.forEach(function(item,idx){
    var num=String(idx+1).padStart(2,'0');
    var div=document.createElement('div');div.className='nav-item'+(idx===0?' active':'');div.dataset.sec=item.id;
    div.innerHTML='<span class="nav-num">'+num+'</span><svg class="nav-ico" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round">'+item.svg+'</svg><span>'+esc(item.label)+'</span>';
    nav.appendChild(div);
  });
}

function showSection(name){document.querySelectorAll('.section').forEach(function(el){el.classList.remove('active');});document.getElementById('sec-'+name).classList.add('active');document.querySelectorAll('.nav-item').forEach(function(el){el.classList.remove('active');});var navItem=document.querySelector('[data-sec="'+name+'"]');if(navItem)navItem.classList.add('active');if(name==='users')loadUsers();if(name==='tools')loadTools();if(name==='files'){if(IS_ADMIN)populateWsSel(bWs).then(loadBrowserFiles);else{bWs=USER_EMAIL;loadBrowserFiles();}}if(name==='logs'){loadLogs();if(!logTimer)logTimer=setInterval(loadLogs,30000);}else{if(logTimer){clearInterval(logTimer);logTimer=null;}}if(name==='account')loadAccount();if(name==='terminal')initTerminal();}

document.getElementById('nav').addEventListener('click',function(e){var item=e.target.closest('.nav-item');if(item)showSection(item.dataset.sec);});

/* ── 01 Users ── */
async function loadUsers(){if(!IS_ADMIN)return;var res=await api('/users');if(!res)return;renderUsers(await res.json());}
function renderUsers(users){document.getElementById('user-count').textContent=users.length+' users';if(!users.length){document.getElementById('users-body').innerHTML='<div class="empty">No users yet.</div>';return;}var rows='';users.forEach(function(u){rows+='<tr><td><strong>'+esc(u.name)+'</strong></td><td style="font-family:monospace;font-size:12px">'+esc(u.email)+'</td><td>'+new Date(u.createdAt).toLocaleDateString()+'</td><td><span class="badge '+(u.fileCount>0?'badge-g':'badge-m')+'">'+u.fileCount+' files</span></td><td style="white-space:nowrap"><button class="sm" data-action="browse" data-email="'+esc(u.email)+'">Browse</button> <button class="sm danger" data-action="wipe" data-email="'+esc(u.email)+'">Wipe</button> <button class="sm danger" data-action="remove" data-email="'+esc(u.email)+'">Remove</button></td></tr>';});document.getElementById('users-body').innerHTML='<table><thead><tr><th>Name</th><th>Email</th><th>First Login</th><th>Workspace</th><th>Actions</th></tr></thead><tbody>'+rows+'</tbody></table>';}
document.getElementById('users-body').addEventListener('click',function(e){var btn=e.target.closest('button[data-action]');if(!btn)return;var a=btn.dataset.action,em=btn.dataset.email;if(a==='browse')browseUserFiles(em);if(a==='wipe')wipeWorkspace(em);if(a==='remove')removeUser(em);});
document.getElementById('add-user-btn').addEventListener('click',async function(){var name=document.getElementById('new-name').value.trim(),email=document.getElementById('new-email').value.trim();if(!email)return;var res=await api('/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,email:email})});if(res&&res.ok){toast('User added');document.getElementById('new-name').value='';document.getElementById('new-email').value='';loadUsers();}else toast('Error',false);});
document.getElementById('refresh-btn').addEventListener('click',loadUsers);
async function removeUser(email){if(!confirm('Remove '+email+'? Workspace files are NOT deleted.'))return;var res=await api('/users/'+encodeURIComponent(email),{method:'DELETE'});if(res&&res.ok){toast('User removed');loadUsers();}else toast('Error',false);}
async function wipeWorkspace(email){if(!confirm('Wipe ALL files for '+email+'? This cannot be undone.'))return;var res=await api('/users/'+encodeURIComponent(email)+'/workspace',{method:'DELETE'});if(res&&res.ok){toast('Workspace wiped');loadUsers();}else toast('Error',false);}
function browseUserFiles(email){bWs=email;bPath='/';bFiles=[];showSection('files');}

/* ── 02 Tools ── */
async function loadTools(){document.getElementById('tools-body').innerHTML='<div class="empty">Loading&hellip;</div>';var res=await api('/tools');if(!res||!res.ok){document.getElementById('tools-body').innerHTML='<div class="empty">Could not load tools.</div>';return;}renderTools(await res.json());}
function renderTools(data){
  var html='';
  html+='<div class="tools-group">Built-in</div>';
  (data.builtin||[]).forEach(function(t){html+=toolCard(t,'builtin');});
  html+='<div class="tools-group">Custom &mdash; Shared Workspace</div>';
  if(data.custom&&data.custom.length){
    data.custom.forEach(function(t){html+=toolCard(t,'custom');});
  }else{
    html+='<div style="font-size:13px;color:var(--cf-text-subtle);padding:4px 0 8px">No custom tools found. Place tool definitions at <code style="font-family:monospace">/tools/{name}/tool.json</code> (directory format) or <code style="font-family:monospace">/tools/{name}.json</code> (flat) in the Shared Workspace.</div>';
  }
  document.getElementById('tools-body').innerHTML=html;
  document.getElementById('tools-body').querySelectorAll('.param-toggle').forEach(function(btn){
    btn.addEventListener('click',function(){var tbl=btn.closest('.tool-card').querySelector('.params-tbl');var open=tbl.style.display==='table';tbl.style.display=open?'none':'table';btn.innerHTML=open?'Params &#9656;':'Params &#9662;';});
  });
  document.getElementById('tools-body').querySelectorAll('.files-toggle').forEach(function(btn){
    btn.addEventListener('click',function(){var fl=btn.closest('.tool-card').querySelector('.tool-files');var open=fl.style.display!=='none';fl.style.display=open?'none':'block';btn.innerHTML=open?'Files &#9656;':'Files &#9662;';});
  });
  if(IS_ADMIN){
    document.getElementById('tools-body').querySelectorAll('button[data-del-tool]').forEach(function(btn){
      btn.addEventListener('click',function(){deleteGlobalTool(btn.dataset.delTool);});
    });
    document.getElementById('tools-body').querySelectorAll('button[data-browse-tool]').forEach(function(btn){
      btn.addEventListener('click',function(){browseUserFiles('shared');setTimeout(function(){var f=btn.dataset.browseDir;if(f){bPath=f;renderTree();}},200);});
    });
    document.getElementById('tools-body').querySelectorAll('button[data-edit-json]').forEach(function(btn){
      btn.addEventListener('click',function(){editToolJson(btn.dataset.editJson);});
    });
  }
}
function toolCard(t,type){
  var raw=t.params||t.schema||[];
  var params=Array.isArray(raw)?raw:Object.entries(raw).map(function(e){return{name:e[0],type:(e[1].type||'string'),description:(e[1].description||''),required:!e[1].optional};});
  var badge=type==='builtin'?'<span class="badge badge-g">built-in</span>':'<span class="badge badge-m">custom</span>';
  var actions=params.length?'<button class="sm param-toggle" style="margin-left:auto">Params &#9656;</button>':'<span style="margin-left:auto"></span>';
  if(type==='custom'&&IS_ADMIN){
    if(t._files&&t._files.length){
      var toolDir=t._files[0].substring(0,t._files[0].lastIndexOf('/'));
      actions+=' <button class="sm files-toggle">Files &#9656;</button>';
      actions+=' <button class="sm" data-browse-tool="'+esc(t.name)+'" data-browse-dir="'+esc(toolDir)+'">Browse</button>';
      actions+=' <button class="sm" data-edit-json="'+esc(toolDir+'/tool.json')+'">Edit JSON</button>';
    }
    actions+=' <button class="sm danger" data-del-tool="'+esc(t.name)+'">Delete</button>';
  }
  var rows='';
  params.forEach(function(p){rows+='<tr><td><code>'+esc(p.name)+'</code></td><td>'+esc(p.type||'string')+'</td><td>'+(p.required?'&#10003;':'&mdash;')+'</td><td>'+esc(p.description||'')+'</td></tr>';});
  var tbl=params.length?'<table class="params-tbl"><thead><tr><th>Parameter</th><th>Type</th><th>Req</th><th>Description</th></tr></thead><tbody>'+rows+'</tbody></table>':'';
  var filesSection='';
  if(t._files&&t._files.length){
    var fileItems=t._files.map(function(f){var name=f.split('/').pop();return'<span style="font-family:monospace;font-size:11px;display:inline-block;background:rgba(235,213,193,.3);padding:1px 6px;border-radius:3px;margin:2px">'+esc(name)+'</span>';}).join(' ');
    filesSection='<div class="tool-files" style="display:none;margin-top:8px;padding:8px 10px;background:var(--cf-bg);border:1px solid rgba(235,213,193,.4)"><div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--cf-text-muted);margin-bottom:5px">Supporting Files</div>'+fileItems+'</div>';
  }
  return'<div class="tool-card"><div class="tool-card-hdr"><span class="tool-name">'+esc(t.name)+'</span>'+badge+actions+'</div><div class="tool-desc">'+esc(t.description||'')+'</div>'+tbl+filesSection+'</div>';
}
async function deleteGlobalTool(name){if(!IS_ADMIN)return;if(!confirm('Delete global tool "'+name+'"?'))return;var res=await api('/global-tools?name='+encodeURIComponent(name),{method:'DELETE'});if(res&&res.ok){toast('Tool deleted');loadTools();}else toast('Error',false);}
function editToolJson(toolJsonPath){var dir=toolJsonPath.substring(0,toolJsonPath.lastIndexOf('/'));bWs='shared';bPath=dir;pendingEditFile=toolJsonPath;showSection('files');}

/* ── 03 Files ── */
async function populateWsSel(selectEmail){if(!IS_ADMIN)return;var sel=document.getElementById('ws-sel');var cur=selectEmail||sel.value||bWs;var res=await api('/users');if(!res)return;var users=await res.json();var opts='<option value="shared">Shared Workspace</option>';users.forEach(function(u){opts+='<option value="'+esc(u.email)+'">'+esc(u.email)+'</option>';});sel.innerHTML=opts;sel.value=cur;bWs=sel.value;}
async function loadBrowserFiles(){var ws=IS_ADMIN?(document.getElementById('ws-sel').value||'shared'):USER_EMAIL;bWs=ws;bFiles=[];resetViewer();document.getElementById('file-tree').innerHTML='<div class="empty">Loading\u2026</div>';var res=await api('/files?workspace='+encodeURIComponent(ws));if(!res)return;bFiles=await res.json();renderTree();if(pendingEditFile){var pef=pendingEditFile;pendingEditFile=null;await viewFile(pef);document.querySelectorAll('#file-tree .tree-row').forEach(function(r){if(r.dataset.path===pef)r.classList.add('selected');});}}
function listDir(){var prefix=bPath==='/'?'/':bPath+'/';var seen=new Set(),dirs=[],files=[];bFiles.forEach(function(f){if(!f.path.startsWith(prefix))return;var rest=f.path.slice(prefix.length);if(!rest)return;var slash=rest.indexOf('/');if(slash===-1){if(!f.path.endsWith('/.keep'))files.push(f);}else{var d=rest.slice(0,slash);if(!seen.has(d)){seen.add(d);dirs.push(d);}}});return{dirs:dirs.sort(),files:files.sort(function(a,b){return a.path.localeCompare(b.path);})};}
function renderTree(){var info=listDir();var all=info.dirs.length+info.files.length;document.getElementById('fb-path').textContent=bPath;document.getElementById('fb-count').textContent=all+' ITEM'+(all!==1?'S':'');var html='';if(bPath!=='/')html+='<div class="tree-row" data-type="up"><span style="font-size:12px;color:var(--cf-text-muted)">&#8593;</span><span class="tree-name">..</span></div>';info.dirs.forEach(function(d){var dp=(bPath==='/'?'':bPath)+'/'+d;html+='<div class="tree-row" data-type="dir" data-path="'+esc(dp)+'"><span style="font-size:14px">&#128193;</span><span class="tree-name">'+esc(d)+'/</span><button class="tree-del" data-path="'+esc(dp)+'" data-deltype="dir" title="Delete directory">&#215;</button></div>';});info.files.forEach(function(f){var name=f.path.split('/').pop();var sz=f.size<1024?f.size+' B':(f.size<1048576?Math.round(f.size/1024)+' KB':Math.round(f.size/1048576)+' MB');var vu=getViewUrl(f.path);var dt=f.updatedAt?fmtDate(f.updatedAt):'';html+='<div class="tree-row" data-type="file" data-path="'+esc(f.path)+'"><span style="font-size:14px">&#128196;</span><span class="tree-name">'+esc(name)+'</span><span class="tree-size">'+sz+'</span>'+(dt?'<span class="tree-date">'+esc(dt)+'</span>':'')+'<button class="tree-dl" data-path="'+esc(f.path)+'" title="Download">&#8595;</button><a class="tree-url" href="'+esc(vu)+'" target="_blank" rel="noopener" title="Open in browser">&#128279;</a><button class="tree-del" data-path="'+esc(f.path)+'" data-deltype="file" title="Delete">&#215;</button></div>';});if(!html)html='<div class="empty" style="padding:20px">Empty directory</div>';document.getElementById('file-tree').innerHTML=html;}
document.getElementById('file-tree').addEventListener('click',function(e){if(e.target.closest('.tree-url'))return;var dl=e.target.closest('.tree-dl');if(dl){e.stopPropagation();downloadFile(dl.dataset.path);return;}var del=e.target.closest('.tree-del');if(del){e.stopPropagation();if(del.dataset.deltype==='dir')delDir(del.dataset.path);else delFile(del.dataset.path);return;}var row=e.target.closest('.tree-row');if(!row)return;var type=row.dataset.type;if(type==='up'){var parts=bPath.split('/').filter(Boolean);parts.pop();bPath=parts.length?'/'+parts.join('/'):'/';renderTree();}else if(type==='dir'){bPath=row.dataset.path;renderTree();}else if(type==='file'){viewFile(row.dataset.path);document.querySelectorAll('.tree-row').forEach(function(r){r.classList.remove('selected');});row.classList.add('selected');}});
function getViewUrl(path){var base=window.location.origin;if(bWs==='shared')return base+'/view?shared=true&file='+encodeURIComponent(path);return base+'/view?user='+encodeURIComponent(bWs)+'&file='+encodeURIComponent(path);}
function fmtDate(ts){if(!ts)return'';var d=new Date(ts>1e11?ts:ts*1000);var now=new Date();var sameYear=now.getFullYear()===d.getFullYear();var date=d.toLocaleDateString([],sameYear?{month:'short',day:'numeric'}:{month:'short',day:'numeric',year:'numeric'});var time=d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});return date+' '+time;}
async function downloadFile(path){var res=await api('/files/read?workspace='+encodeURIComponent(bWs)+'&path='+encodeURIComponent(path));if(!res||!res.ok){toast('Download failed',false);return;}var blob=await res.blob();var url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download=path.split('/').pop()||'file';document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(url);document.body.removeChild(a);},100);}
function resetViewer(){currentEditPath='';document.getElementById('viewer-path').textContent='Select a file to view its contents';var editor=document.getElementById('file-editor');editor.value='';editor.setAttribute('readonly','');document.getElementById('save-file-btn').style.display='none';}
async function viewFile(path){currentEditPath=path;document.getElementById('viewer-path').textContent=path;var editor=document.getElementById('file-editor');editor.value='Loading\u2026';editor.removeAttribute('readonly');document.getElementById('save-file-btn').style.display='';var res=await api('/files/read?workspace='+encodeURIComponent(bWs)+'&path='+encodeURIComponent(path));if(!res)return;var content=await res.text();editor.value=content;}
async function delFile(path){if(!confirm('Delete '+path+'?'))return;var res=await api('/files?workspace='+encodeURIComponent(bWs)+'&path='+encodeURIComponent(path),{method:'DELETE'});if(res&&res.ok){toast('Deleted');bFiles=bFiles.filter(function(f){return f.path!==path;});renderTree();}else toast('Delete failed',false);}
async function delDir(dirPath){var children=bFiles.filter(function(f){return f.path===dirPath+'/.keep'||f.path.startsWith(dirPath+'/');});var count=children.filter(function(f){return!f.path.endsWith('/.keep');}).length;var msg=count>0?'Delete directory '+dirPath+' and all '+count+' file(s) inside?':'Delete empty directory '+dirPath+'?';if(!confirm(msg))return;var failed=0;for(var i=0;i<children.length;i++){var r=await api('/files?workspace='+encodeURIComponent(bWs)+'&path='+encodeURIComponent(children[i].path),{method:'DELETE'});if(!r||!r.ok)failed++;}if(failed)toast(failed+' deletion(s) failed',false);else toast('Directory deleted');loadBrowserFiles();}
async function saveFile(){if(!currentEditPath)return;var content=document.getElementById('file-editor').value;var res=await api('/files/write?workspace='+encodeURIComponent(bWs)+'&path='+encodeURIComponent(currentEditPath),{method:'POST',body:content});if(res&&res.ok)toast('Saved');else toast('Save failed',false);}
document.getElementById('save-file-btn').addEventListener('click',saveFile);
document.getElementById('ws-sel').addEventListener('change',function(){bWs=this.value;bPath='/';bFiles=[];loadBrowserFiles();});

/* ── 04 Logs ── */
var LOG_LEVEL_COLORS={info:'var(--cf-text-muted)',warn:'#b45309',error:'var(--cf-error)'};
var LOG_LEVEL_BG={info:'rgba(235,213,193,.3)',warn:'rgba(180,83,9,.08)',error:'rgba(220,38,38,.08)'};
async function loadLogs(){if(!IS_ADMIN)return;document.getElementById('log-count').textContent='Loading\u2026';var res=await api('/logs?limit=200&level='+logLevel);if(!res)return;var logs=await res.json();renderLogs(logs);}
function renderLogs(logs){document.getElementById('log-count').textContent=logs.length+' entries';if(!logs.length){document.getElementById('logs-body').innerHTML='<div class="empty">No log entries yet. Actions in the admin panel will appear here.</div>';return;}var html='<table style="font-size:12px"><thead><tr><th style="width:170px">Time</th><th style="width:60px">Level</th><th style="width:200px">Event</th><th>Data</th></tr></thead><tbody>';logs.forEach(function(l){var d=new Date(l.ts);var ts=d.toLocaleDateString()+' '+d.toLocaleTimeString();var dataStr=Object.keys(l.data||{}).length?JSON.stringify(l.data):'';html+='<tr style="background:'+LOG_LEVEL_BG[l.level||'info']+'">'+'<td style="font-family:monospace;font-size:11px;color:var(--cf-text-muted);white-space:nowrap">'+esc(ts)+'</td>'+'<td><span style="font-size:10px;font-weight:700;text-transform:uppercase;color:'+LOG_LEVEL_COLORS[l.level||'info']+'">'+esc(l.level||'info')+'</span></td>'+'<td style="font-family:monospace;font-size:11px">'+esc(l.event||'')+'</td>'+'<td style="font-family:monospace;font-size:11px;color:var(--cf-text-muted);word-break:break-all">'+esc(dataStr)+'</td>'+'</tr>';});html+='</tbody></table>';document.getElementById('logs-body').innerHTML=html;}
document.getElementById('log-filter').addEventListener('click',function(e){var btn=e.target.closest('button[data-lvl]');if(!btn)return;logLevel=btn.dataset.lvl;document.querySelectorAll('#log-filter button').forEach(function(b){b.classList.remove('active-filter');b.style.fontWeight='';});btn.classList.add('active-filter');btn.style.fontWeight='600';loadLogs();});
document.getElementById('refresh-logs-btn').addEventListener('click',loadLogs);

/* ── 05 My Account ── */
async function loadAccount(){var res=await api('/me');if(!res)return;var data=await res.json();document.getElementById('account-email').textContent=data.email;document.getElementById('account-name').textContent=data.name;document.getElementById('account-created').textContent=new Date(data.createdAt).toLocaleDateString();document.getElementById('account-files').textContent=data.fileCount+' files';}

/* ── Terminal ── */
var termInited=false,termWs=null,termInstance=null;
var TERM_CMDS=[
  {label:'System info',cmd:'uname -a\\r'},
  {label:'Python version',cmd:'python3 --version\\r'},
  {label:'Node version',cmd:'node --version\\r'},
  {label:'List /workspace',cmd:'ls -la /workspace\\r'},
  {label:'Disk usage',cmd:'df -h /\\r'},
  {label:'Cowsay',cmd:'pip3 install cowsay -q && python3 -c \\'import cowsay; cowsay.cow("Hello!")\\' \\r'},
  {label:'Fetch URL',cmd:'node -e "fetch(\\'https://httpbin.org/ip\\').then(r=>r.json()).then(console.log)"\\r'},
  {label:'Write & run Python',cmd:'echo \\'import math; print(math.pi)\\' > /tmp/demo.py && python3 /tmp/demo.py\\r'}
];
async function initTerminal(){
  if(termInited)return;
  termInited=true;
  var container=document.getElementById('xterm-mount');
  if(!container)return;
  try{
    // Use the official SandboxAddon — same implementation as sandbox-sdk.site.
    // It manages the WebSocket, binary encoding, resize, ready/exit/error messages
    // and automatic reconnection after a session ends (e.g. after typing "exit").
    var mods=await Promise.all([
      import('https://esm.sh/@xterm/xterm@5'),
      import('https://esm.sh/@xterm/addon-fit@0.10.0'),
      import('https://esm.sh/@cloudflare/sandbox@0.8.4/xterm')
    ]);
    var Terminal=mods[0].Terminal,FitAddon=mods[1].FitAddon,SandboxAddon=mods[2].SandboxAddon;
    var term=new Terminal({
      fontFamily:"ui-monospace,'Cascadia Code','Source Code Pro',Menlo,monospace",
      fontSize:13,lineHeight:1.4,cursorBlink:true,cursorStyle:'bar',allowProposedApi:true,
      theme:{
        background:'#160a00',foreground:'#f5e6d3',cursor:'#FF4801',cursorAccent:'#160a00',
        selectionBackground:'rgba(255,72,1,0.3)',
        black:'#1a0800',red:'#dc2626',green:'#16a34a',yellow:'#eab308',
        blue:'#2563eb',magenta:'#9616ff',cyan:'#06b6d4',white:'#f5e6d3',
        brightBlack:'#6b3a1f',brightRed:'#ef4444',brightGreen:'#22c55e',
        brightYellow:'#facc15',brightBlue:'#3b82f6',brightMagenta:'#a855f7',
        brightCyan:'#22d3ee',brightWhite:'#ffffff'
      }
    });
    termInstance=term;
    var fit=new FitAddon();
    var addon=new SandboxAddon({
      getWebSocketUrl:function(o){
        // Server derives the sandbox ID from the session cookie — ignore o.sandboxId
        return o.origin+'/dash/ws/terminal';
      },
      onStateChange:function(state,err){
        if(state==='connected'){
          var c=document.getElementById('terminal-connecting');
          if(c)c.style.display='none';
        }
        if(err)term.write('\\r\\n['+err.message+']\\r\\n');
      }
    });
    term.loadAddon(fit);
    term.loadAddon(addon);
    term.open(container);
    fit.fit();
    new ResizeObserver(function(){fit.fit();}).observe(container);
    // sandboxId is ignored server-side (derived from session cookie)
    addon.connect({sandboxId:'session'});
    // Demo command buttons — SandboxAddon.sendData handles binary encoding
    var btnsEl=document.getElementById('term-cmds');
    if(btnsEl){
      TERM_CMDS.forEach(function(c){
        var btn=document.createElement('button');
        btn.textContent=c.label;
        btn.addEventListener('click',function(){addon.sendData(c.cmd);term.focus();});
        btnsEl.appendChild(btn);
      });
    }
  }catch(err){
    var conn=document.getElementById('terminal-connecting');
    if(conn)conn.innerHTML='<span style="color:rgba(245,100,60,.8);font-size:13px">Failed to load terminal: '+esc(String(err))+'</span>';
  }
}

/* ── Init ── */
window.addEventListener('load',function(){buildNav();showSection(navItems[0].id);});
</script>
<style>
.active-filter{font-weight:600!important;border-style:solid!important;background:var(--cf-bg-hover)!important;color:var(--cf-text)!important}
@keyframes sig{0%,100%{opacity:.3;transform:scaleY(.5)}50%{opacity:1;transform:scaleY(1)}}
.sig-bar{animation:sig 1s ease-in-out infinite;transform-origin:bottom;animation-delay:calc(var(--d)*0.12s)}
.sig-bar:nth-child(1){height:10px}.sig-bar:nth-child(2){height:13px}.sig-bar:nth-child(3){height:16px}.sig-bar:nth-child(4){height:19px}.sig-bar:nth-child(5){height:22px}
</style>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie":   sessionCookie,
    },
  });
}

// ─── Chat page ────────────────────────────────────────────────────────────────
// Serves the embedded OpenCode web UI at /chat.
// The serverUrl and directory are baked into the HTML so the OpenCode mount
// knows where to connect without additional round-trips.

function serveChatPage(
  user: AuthenticatedUser,
  sandboxId: string,
  request: Request,
  sessionCookie: string,
): Response {
  const origin    = new URL(request.url).origin;
  const serverUrl = `${origin}/chat/oc/${sandboxId}`;
  const directory = "/home/user/workspace";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Sandbox — Chat</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NiA2NiI+PHJlY3Qgd2lkdGg9IjY2IiBoZWlnaHQ9IjY2IiByeD0iOSIgZmlsbD0iI0ZGNDgwMSIvPjxnIHRyYW5zZm9ybT0idHJhbnNsYXRlKDAsMTgpIiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTUyLjY4OCAxMy4wMjhjLS4yMiAwLS40MzcuMDA4LS42NTQuMDE1YS4zLjMgMCAwIDAtLjEwMi4wMjQuMzcuMzcgMCAwIDAtLjIzNi4yNTVsLS45MyAzLjI0OWMtLjQwMSAxLjM5Ny0uMjUyIDIuNjg3LjQyMiAzLjYzNC42MTguODc2IDEuNjQ2IDEuMzkgMi44OTQgMS40NWw1LjA0NS4zMDZhLjQ1LjQ1IDAgMCAxIC40MzUuNDEuNS41IDAgMCAxLS4wMjUuMjIzLjY0LjY0IDAgMCAxLS41NDcuNDI2bC01LjI0Mi4zMDZjLTIuODQ4LjEzMi01LjkxMiAyLjQ1Ni02Ljk4NyA1LjI5bC0uMzc4IDFhLjI4LjI4IDAgMCAwIC4yNDguMzgyaDE4LjA1NGEuNDguNDggMCAwIDAgLjQ2NC0uMzVjLjMyLTEuMTUzLjQ4Mi0yLjM0NC40OC0zLjU0IDAtNy4yMi01Ljc5LTEzLjA3Mi0xMi45MzMtMTMuMDcyTTQ0LjgwNyAyOS41NzhsLjMzNC0xLjE3NWMuNDAyLTEuMzk3LjI1My0yLjY4Ny0uNDItMy42MzQtLjYyLS44NzYtMS42NDctMS4zOS0yLjg5Ni0xLjQ1bC0yMy42NjUtLjMwNmEuNDcuNDcgMCAwIDEtLjM3NC0uMTk5LjUuNSAwIDAgMS0uMDUyLS40MzQuNjQuNjQgMCAwIDEgLjU1Mi0uNDI2bDIzLjg4Ni0uMzA2YzIuODM2LS4xMzEgNS45LTIuNDU2IDYuOTc1LTUuMjlsMS4zNjItMy42YS45LjkgMCAwIDAgLjA0LS40NzdDNDguOTk3IDUuMjU5IDQyLjc4OSAwIDM1LjM2NyAwYy02Ljg0MiAwLTEyLjY0NyA0LjQ2Mi0xNC43MyAxMC42NjVhNi45MiA2LjkyIDAgMCAwLTQuOTExLTEuMzc0Yy0zLjI4LjMzLTUuOTIgMy4wMDItNi4yNDYgNi4zMThhNy4yIDcuMiAwIDAgMCAuMTggMi40NzJDNC4zIDE4LjI0MSAwIDIyLjY3OSAwIDI4LjEzM3EwIC43NC4xMDYgMS40NTNhLjQ2LjQ2IDAgMCAwIC40NTcuNDAyaDQzLjcwNGEuNTcuNTcgMCAwIDAgLjU0LS40MTgiLz48L2c+PC9zdmc+">
<link rel="stylesheet" href="/opencode-ui/opencode-mount.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden;background:#111;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
#chat-nav{position:fixed;top:0;left:0;right:0;height:36px;background:#1C0A00;display:flex;align-items:center;gap:12px;padding:0 16px;z-index:9999;border-bottom:1px solid #3a1500}
#chat-nav a{font-size:11px;color:rgba(245,230,211,.6);text-decoration:none;padding:2px 8px;border-radius:4px;transition:all .12s}
#chat-nav a:hover,#chat-nav a.active{color:#f5e6d3;background:rgba(255,72,1,.2)}
#chat-nav .sep{color:rgba(245,230,211,.2);font-size:14px}
#root{position:fixed;top:36px;left:0;right:0;bottom:0}
#loader{position:fixed;top:36px;left:0;right:0;bottom:0;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#111;gap:16px;color:rgba(245,230,211,.7);font-size:13px}
.spinner{width:32px;height:32px;border:3px solid rgba(255,72,1,.2);border-top-color:#FF4801;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#loader-msg{font-size:12px;color:rgba(245,230,211,.4)}
</style>
</head>
<body>
<nav id="chat-nav">
  <a href="/dash" id="nav-dash">Dashboard</a>
  <span class="sep">|</span>
  <a href="/chat" class="active">Chat</a>
  <span class="sep">|</span>
  <span style="font-size:11px;color:rgba(245,230,211,.3);font-family:monospace">${escapeHtml(user.email)}</span>
</nav>
<div id="loader">
  <div class="spinner"></div>
  <div>Starting AI Sandbox…</div>
  <div id="loader-msg">Spinning up your container</div>
</div>
<div id="root"></div>
<script type="module">
  // Intercept Dashboard link before SolidJS HashRouter's global click handler
  document.getElementById("nav-dash").addEventListener("click", (e) => {
    e.stopImmediatePropagation();
    e.preventDefault();
    window.location.href = "/dash";
  }, true);

  const serverUrl  = ${JSON.stringify(serverUrl)};
  const statusUrl  = ${JSON.stringify(`/chat/status/${sandboxId}`)};
  const directory  = ${JSON.stringify(directory)};
  let mounted = false;

  async function isReady() {
    try {
      // First check our status endpoint (fast — DO state check, no container request)
      const s = await fetch(statusUrl, { signal: AbortSignal.timeout(4000) });
      if (s.ok) {
        const { status } = await s.json();
        if (status === "ready") return true;
        document.getElementById("loader-msg").textContent =
          status === "starting" ? "OpenCode is starting…" : "Waiting for container…";
        return false;
      }
    } catch { /* network error — keep retrying */ }
    return false;
  }

  async function mountUI() {
    const loader = document.getElementById("loader");
    loader.querySelector("div:nth-child(2)").textContent = "Loading interface…";
    document.getElementById("loader-msg").textContent = "";
    try {
      const { mount } = await import("/opencode-ui/opencode-mount.js");
      mount(document.getElementById("root"), { serverUrl, directory });
      loader.style.display = "none";
      mounted = true;
    } catch (err) {
      loader.querySelector("div:nth-child(2)").textContent = "Failed to load OpenCode UI";
      document.getElementById("loader-msg").textContent = err.message;
    }
  }

  async function poll() {
    while (!mounted) {
      if (await isReady()) { await mountUI(); return; }
      await new Promise(r => setTimeout(r, 3000));
    }
  }

  poll();
</script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie":   sessionCookie,
    },
  });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Chat API ─────────────────────────────────────────────────────────────────
// /chat/api/* — configuration and MCP status endpoints.

async function handleChatApi(
  request: Request,
  url: URL,
  env: Env,
  user: AuthenticatedUser,
): Promise<Response> {
  const method = request.method.toUpperCase();
  const path   = url.pathname.replace(/^\/chat\/api/, "");

  // Stub for the user's ChatSession DO
  const chatSessionId = env.CHAT_SESSION.idFromName(user.email);
  const chatSession   = env.CHAT_SESSION.get(chatSessionId) as unknown as {
    getUserConfig(): Promise<ChatUserConfig>;
    updateUserConfig(p: Partial<ChatUserConfig>): Promise<ChatUserConfig>;
    getMcpStatuses(sandboxId: string): Promise<Record<string, unknown>>;
    authenticateMcp(sandboxId: string, name: string): Promise<unknown>;
  };

  const sandboxId = `chat-${emailToNamespace(user.email)}`;

  // GET /chat/api/config — return user's chat configuration
  if (method === "GET" && path === "/config") {
    const config = await chatSession.getUserConfig();
    return jsonResp({ ...config, availableModels: AVAILABLE_MODELS });
  }

  // PATCH /chat/api/config — update user's chat configuration
  if (method === "PATCH" && path === "/config") {
    const body = await request.json<Partial<ChatUserConfig>>();
    // Validate model if provided
    if (body.model && !AVAILABLE_MODELS[body.model]) {
      return jsonResp({ error: `Unknown model: ${body.model}` }, 400);
    }
    const updated = await chatSession.updateUserConfig(body);
    return jsonResp(updated);
  }

  // GET /chat/api/models — list available Workers AI models
  if (method === "GET" && path === "/models") {
    return jsonResp({ models: AVAILABLE_MODELS });
  }

  // GET /chat/api/mcp — MCP server statuses
  if (method === "GET" && path === "/mcp") {
    try {
      const statuses = await chatSession.getMcpStatuses(sandboxId);
      return jsonResp(statuses);
    } catch (err) {
      return jsonResp({ error: String(err) }, 503);
    }
  }

  // POST /chat/api/mcp/:name/auth — trigger MCP OAuth for a server
  const authMatch = path.match(/^\/mcp\/([^/]+)\/auth$/);
  if (method === "POST" && authMatch) {
    const name = decodeURIComponent(authMatch[1]);
    try {
      const result = await chatSession.authenticateMcp(sandboxId, name);
      return jsonResp(result);
    } catch (err) {
      return jsonResp({ error: String(err) }, 502);
    }
  }

  return jsonResp({ error: "Not found" }, 404);
}
