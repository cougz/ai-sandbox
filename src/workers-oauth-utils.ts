// workers-oauth-utils.ts — copied from github.com/cloudflare/ai (official example)
// OAuth utility functions with CSRF and state validation security fixes

import type { AuthRequest, ClientInfo } from "@cloudflare/workers-oauth-provider";

export class OAuthError extends Error {
  constructor(
    public code: string,
    public description: string,
    public statusCode = 400,
  ) {
    super(description);
    this.name = "OAuthError";
  }
  toResponse(): Response {
    return new Response(JSON.stringify({ error: this.code, error_description: this.description }), {
      status: this.statusCode,
      headers: { "Content-Type": "application/json" },
    });
  }
}

export interface OAuthStateResult { stateToken: string; }
export interface ValidateStateResult { oauthReqInfo: AuthRequest; clearCookie: string; }
export interface CSRFProtectionResult { token: string; setCookie: string; }
export interface ValidateCSRFResult { clearCookie: string; }

export function sanitizeText(text: string): string {
  return text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

export function sanitizeUrl(url: string): string {
  const normalized = url.trim();
  if (!normalized.length) return "";
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) return "";
  }
  let parsedUrl: URL;
  try { parsedUrl = new URL(normalized); } catch { return ""; }
  const scheme = parsedUrl.protocol.slice(0, -1).toLowerCase();
  if (!["https", "http"].includes(scheme)) return "";
  return normalized;
}

export function generateCSRFProtection(): CSRFProtectionResult {
  const csrfCookieName = "__Host-CSRF_TOKEN";
  const token = crypto.randomUUID();
  const setCookie = `${csrfCookieName}=${token}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600`;
  return { token, setCookie };
}

export function validateCSRFToken(formData: FormData, request: Request): ValidateCSRFResult {
  const csrfCookieName = "__Host-CSRF_TOKEN";
  const tokenFromForm = formData.get("csrf_token");
  if (!tokenFromForm || typeof tokenFromForm !== "string")
    throw new OAuthError("invalid_request", "Missing CSRF token in form data", 400);
  const cookieHeader = request.headers.get("Cookie") || "";
  const csrfCookie = cookieHeader.split(";").map(c => c.trim()).find(c => c.startsWith(`${csrfCookieName}=`));
  const tokenFromCookie = csrfCookie ? csrfCookie.substring(csrfCookieName.length + 1) : null;
  if (!tokenFromCookie) throw new OAuthError("invalid_request", "Missing CSRF token cookie", 400);
  if (tokenFromForm !== tokenFromCookie) throw new OAuthError("invalid_request", "CSRF token mismatch", 400);
  return { clearCookie: `${csrfCookieName}=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0` };
}

export async function createOAuthState(oauthReqInfo: AuthRequest, kv: KVNamespace, stateTTL = 600): Promise<OAuthStateResult> {
  const stateToken = crypto.randomUUID();
  await kv.put(`oauth:state:${stateToken}`, JSON.stringify(oauthReqInfo), { expirationTtl: stateTTL });
  return { stateToken };
}

export async function validateOAuthState(request: Request, kv: KVNamespace): Promise<ValidateStateResult> {
  const url = new URL(request.url);
  const stateFromQuery = url.searchParams.get("state");
  if (!stateFromQuery) throw new OAuthError("invalid_request", "Missing state parameter", 400);
  const storedDataJson = await kv.get(`oauth:state:${stateFromQuery}`);
  if (!storedDataJson) throw new OAuthError("invalid_request", "Invalid or expired state", 400);
  let oauthReqInfo: AuthRequest;
  try { oauthReqInfo = JSON.parse(storedDataJson) as AuthRequest; }
  catch { throw new OAuthError("server_error", "Invalid state data", 500); }
  await kv.delete(`oauth:state:${stateFromQuery}`);
  return { oauthReqInfo, clearCookie: "" };
}

export async function isClientApproved(request: Request, clientId: string, cookieSecret: string): Promise<boolean> {
  const approvedClients = await getApprovedClientsFromCookie(request, cookieSecret);
  return approvedClients?.includes(clientId) ?? false;
}

export async function addApprovedClient(request: Request, clientId: string, cookieSecret: string): Promise<string> {
  const name = "__Host-APPROVED_CLIENTS";
  const existing = (await getApprovedClientsFromCookie(request, cookieSecret)) || [];
  const updated = Array.from(new Set([...existing, clientId]));
  const payload = JSON.stringify(updated);
  const sig = await signData(payload, cookieSecret);
  return `${name}=${sig}.${btoa(payload)}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=2592000`;
}

export interface ApprovalDialogOptions {
  client: ClientInfo | null;
  server: { name: string; logo?: string; description?: string };
  state: Record<string, unknown>;
  csrfToken: string;
  setCookie: string;
}

export function renderApprovalDialog(request: Request, options: ApprovalDialogOptions): Response {
  const { client, server, state, csrfToken, setCookie } = options;
  const encodedState = btoa(JSON.stringify(state));
  const serverName = sanitizeText(server.name);
  const clientName = client?.clientName ? sanitizeText(client.clientName) : "OpenCode";
  const serverDescription = server.description ? sanitizeText(server.description) : "";
  const logoUrl = server.logo ? sanitizeText(sanitizeUrl(server.logo)) : "";

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${clientName} | Authorization</title>
<style>
html{color-scheme:light}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#FFFBF5;color:#521000;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#FFFDFB;border:1px solid #EBD5C1;padding:32px;max-width:420px;width:100%;position:relative}
.cb{position:absolute;width:8px;height:8px;border:1px solid #EBD5C1;border-radius:1.5px;background:#FFFBF5}
.logo{width:48px;height:48px;border-radius:8px;object-fit:contain;margin-bottom:16px}
h1{font-size:18px;font-weight:500;margin-bottom:8px;letter-spacing:-0.02em}
p{font-size:13px;color:rgba(82,16,0,0.7);line-height:1.6;margin-bottom:20px}
.actions{display:flex;gap:10px;justify-content:flex-end}
button{padding:9px 20px;border-radius:9999px;font-size:13px;font-weight:500;cursor:pointer;border:1px solid #EBD5C1;background:#FFFDFB;color:rgba(82,16,0,0.7);font-family:inherit}
button.primary{background:#FF4801;color:#fff;border-color:transparent}
</style></head><body>
<div class="card">
  <div class="cb" style="top:-4px;left:-4px"></div><div class="cb" style="top:-4px;right:-4px"></div>
  <div class="cb" style="bottom:-4px;left:-4px"></div><div class="cb" style="bottom:-4px;right:-4px"></div>
  ${logoUrl ? `<img src="${logoUrl}" class="logo" alt="${serverName}">` : ""}
  <h1><strong>${serverName}</strong></h1>
  ${serverDescription ? `<p>${serverDescription}</p>` : ""}
  <p><strong>${clientName}</strong> is requesting access. By approving, you will be redirected to sign in with your Cloudflare Access account.</p>
  <form method="post" action="${new URL(request.url).pathname}">
    <input type="hidden" name="state" value="${encodedState}">
    <input type="hidden" name="csrf_token" value="${csrfToken}">
    <div class="actions">
      <button type="button" onclick="window.history.back()">Cancel</button>
      <button type="submit" class="primary">Approve</button>
    </div>
  </form>
</div></body></html>`;

  return new Response(html, {
    headers: {
      "Content-Security-Policy": "frame-ancestors 'none'",
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": setCookie,
      "X-Frame-Options": "DENY",
    },
  });
}

export function getUpstreamAuthorizeUrl(params: { upstream_url: string; client_id: string; redirect_uri: string; scope: string; state: string }): string {
  const url = new URL(params.upstream_url);
  url.searchParams.set("client_id", params.client_id);
  url.searchParams.set("redirect_uri", params.redirect_uri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", params.scope);
  url.searchParams.set("state", params.state);
  return url.toString();
}

export async function fetchUpstreamAuthToken(params: { upstream_url: string; client_id: string; client_secret: string; code?: string; redirect_uri: string }): Promise<[string, string, null] | [null, null, Response]> {
  if (!params.code) return [null, null, new Response("Missing authorization code", { status: 400 })];
  const resp = await fetch(params.upstream_url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({ client_id: params.client_id, client_secret: params.client_secret, code: params.code, grant_type: "authorization_code", redirect_uri: params.redirect_uri }),
  });
  if (!resp.ok) return [null, null, new Response(`Token exchange failed: ${await resp.text()}`, { status: resp.status })];
  const body = await resp.json<{ access_token?: string; id_token?: string }>();
  if (!body.access_token) return [null, null, new Response("Missing access token", { status: 400 })];
  if (!body.id_token) return [null, null, new Response("Missing id token", { status: 400 })];
  return [body.access_token, body.id_token, null];
}

export interface Props {
  accessToken: string;
  email: string;
  login: string;
  name: string;
  [key: string]: unknown;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async function getApprovedClientsFromCookie(request: Request, cookieSecret: string): Promise<string[] | null> {
  const name = "__Host-APPROVED_CLIENTS";
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;
  const targetCookie = cookieHeader.split(";").map(c => c.trim()).find(c => c.startsWith(`${name}=`));
  if (!targetCookie) return null;
  const parts = targetCookie.substring(name.length + 1).split(".");
  if (parts.length !== 2) return null;
  const [sig, b64payload] = parts;
  const payload = atob(b64payload);
  if (!await verifySignature(sig, payload, cookieSecret)) return null;
  try {
    const parsed = JSON.parse(payload);
    if (!Array.isArray(parsed) || !parsed.every(i => typeof i === "string")) return null;
    return parsed as string[];
  } catch { return null; }
}

async function signData(data: string, secret: string): Promise<string> {
  const key = await importKey(secret);
  const buf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifySignature(hex: string, data: string, secret: string): Promise<boolean> {
  const key = await importKey(secret);
  try {
    const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
    return await crypto.subtle.verify("HMAC", key, bytes.buffer, new TextEncoder().encode(data));
  } catch { return false; }
}

async function importKey(secret: string): Promise<CryptoKey> {
  if (!secret) throw new Error("cookieSecret is required");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
