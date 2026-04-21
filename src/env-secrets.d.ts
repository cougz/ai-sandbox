// Runtime secrets — set via `wrangler secret put`.
// These are not included in auto-generated worker-configuration.d.ts
// because wrangler only generates types for bindings declared in wrangler.jsonc.
//
// Also declares additional bindings that are added after the last `wrangler types` run
// (CHAT_SESSION, AI) so they are visible everywhere the global Env is used.
interface Env {
  ADMIN_EMAILS: string;
  ADMIN_SECRET: string;
  COOKIE_ENCRYPTION_KEY: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  ACCESS_TOKEN_URL: string;
  ACCESS_AUTHORIZATION_URL: string;
  ACCESS_JWKS_URL: string;

  // Container DO — re-exported from @cloudflare/sandbox.
  // Typed as any to avoid the DurableObjectNamespace<Sandbox<any>> mismatch
  // until `wrangler types` is re-run with the updated wrangler.jsonc.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  Sandbox: DurableObjectNamespace<any>;

  // ChatSession DO — one per user, manages OpenCode lifecycle for /chat.
  CHAT_SESSION: DurableObjectNamespace;

  // Workers AI binding (ai: { binding: "AI" } in wrangler.jsonc).
  // Full type is `Ai` from @cloudflare/workers-types; any until wrangler types regenerated.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  AI: any;

  // AUD tag of the /chat CF Access self-hosted application.
  // Used to validate the cf-access-jwt-assertion header on page load.
  // Set via wrangler.jsonc vars (not a secret — AUD tags are non-sensitive).
  CHAT_AUD: string;
}
