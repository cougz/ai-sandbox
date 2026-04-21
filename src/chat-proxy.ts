/**
 * HTTP proxy for /chat/oc/* and /chat/oauth/* routes.
 *
 * Forwards requests from the browser to the OpenCode server running inside
 * the Cloudflare Container on port 4096.
 *
 * /chat/oc/{sandboxId}/*   → OpenCode HTTP API (authenticated by CF Access)
 * /chat/oauth/{sandboxId}/* → MCP OAuth callbacks (intentionally unauthenticated;
 *                             OpenCode's OAuth state parameter is the CSRF boundary)
 *
 * Pattern adapted from let-it-slide (app/src/server/opencode-proxy.ts).
 */

import { getSandbox } from "@cloudflare/sandbox";
import type { Env } from "./agent";

const OPENCODE_PORT              = 4096;
const SANDBOX_START_TIMEOUT_MS   = 30_000;
const CONTAINER_FETCH_TIMEOUT_MS = 30_000;

/** HTTP status codes that must have a null body per the Fetch spec. */
const NULL_BODY_STATUSES = new Set([101, 204, 304]);

/** CSP applied to the OAuth callback page returned by OpenCode. */
const OAUTH_CALLBACK_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  "img-src data:",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

// ─── Route matching ───────────────────────────────────────────────────────────

interface ProxyTarget {
  sandboxId: string;
  /** Path to forward to the container (without the /chat/oc/{id} prefix). */
  rest:      string;
  isOAuth:   boolean;
}

function matchProxyTarget(url: URL): ProxyTarget | null {
  const { pathname } = url;

  // /chat/oc/{sandboxId}/... → standard OpenCode API proxy
  if (pathname.startsWith("/chat/oc/")) {
    const after    = pathname.slice("/chat/oc/".length);
    const slashIdx = after.indexOf("/");
    // No trailing path — treat as root (e.g. OpenCode connectivity check)
    const sandboxId = slashIdx === -1 ? after : after.slice(0, slashIdx);
    const rest      = slashIdx === -1 ? "/"  : after.slice(slashIdx);
    if (!sandboxId) return null;
    return { sandboxId, rest, isOAuth: false };
  }

  // /chat/oauth/{sandboxId}/... → MCP OAuth callback
  // OpenCode matches the full redirectUri pathname, so we forward the whole path.
  if (pathname.startsWith("/chat/oauth/")) {
    const after    = pathname.slice("/chat/oauth/".length);
    const slashIdx = after.indexOf("/");
    if (slashIdx === -1) return null;
    const sandboxId = after.slice(0, slashIdx);
    if (!sandboxId) return null;
    return { sandboxId, rest: pathname, isOAuth: true };
  }

  return null;
}

// ─── Proxy helper ─────────────────────────────────────────────────────────────

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms,
    );
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e: unknown) => { clearTimeout(timer); reject(e); },
    );
  });
}

// ─── Main export ─────────────────────────────────────────────────────────────

/**
 * Try to handle a chat proxy request.
 * Returns null if the URL does not match /chat/oc/* or /chat/oauth/*.
 */
export async function proxyChatRequest(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const url    = new URL(request.url);
  const target = matchProxyTarget(url);
  if (!target) return null;

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sandbox = getSandbox((env as any).Sandbox, target.sandboxId);

    // For OAuth callbacks the container may not be warm yet — wake the OpenCode
    // port first so the in-process callback listener is ready when we forward.
    if (target.isOAuth) {
      await withTimeout(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (sandbox as any).start(undefined, { portToCheck: OPENCODE_PORT }),
        SANDBOX_START_TIMEOUT_MS,
        "sandbox.start",
      );
    }

    const targetUrl  = new URL(target.rest + url.search, `http://localhost:${OPENCODE_PORT}`);
    const proxyReq   = new Request(targetUrl.toString(), {
      method:   request.method,
      headers:  request.headers,
      body:     request.body,
      redirect: "manual",
    });

    const response: Response = await withTimeout<Response>(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (sandbox as any).containerFetch(proxyReq, OPENCODE_PORT) as Promise<Response>,
      CONTAINER_FETCH_TIMEOUT_MS,
      "sandbox.containerFetch",
    );

    // Null-body statuses
    if (NULL_BODY_STATUSES.has(response.status)) {
      const headers = new Headers(response.headers);
      if (target.isOAuth && headers.get("content-type")?.includes("text/html")) {
        headers.set("content-security-policy", OAUTH_CALLBACK_CSP);
      }
      return new Response(null, {
        status:     response.status,
        statusText: response.statusText,
        headers,
      });
    }

    // Container not ready — tell the client to retry
    if (!response.ok) {
      const body = await response.text();
      if (body.includes("not listening") || body.includes("Error proxying")) {
        return new Response(JSON.stringify({ error: "OpenCode server is starting, please retry" }), {
          status:  503,
          headers: { "Content-Type": "application/json", "Retry-After": "2" },
        });
      }
      // Pass through other non-OK responses (strip Content-Length as body may be re-encoded)
      const headers = new Headers(response.headers);
      headers.delete("content-length");
      return new Response(body, { status: response.status, statusText: response.statusText, headers });
    }

    const responseHeaders = new Headers(response.headers);
    if (target.isOAuth && responseHeaders.get("content-type")?.includes("text/html")) {
      responseHeaders.set("content-security-policy", OAUTH_CALLBACK_CSP);
    }

    // Pass through response — preserve body stream for SSE
    return new Response(response.body, {
      status:     response.status,
      statusText: response.statusText,
      headers:    responseHeaders,
    });

  } catch (err) {
    console.error("[chat-proxy] Request failed", {
      sandboxId: target.sandboxId,
      path:      url.pathname,
      error:     err instanceof Error ? err.message : String(err),
    });
    return Response.json(
      { error: err instanceof Error ? err.message : "Proxy error" },
      { status: 502 },
    );
  }
}
