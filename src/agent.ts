import OAuthProvider from "@cloudflare/workers-oauth-provider";
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
import { handleRequest } from "./access-handler";
import type { Props } from "./workers-oauth-utils";

const CONTENT_TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  md:   "text/markdown; charset=utf-8",
  txt:  "text/plain; charset=utf-8",
  csv:  "text/csv; charset=utf-8",
};

// ─── Env ──────────────────────────────────────────────────────────────────────

export interface Env {
  // Bindings
  LOADER: WorkerLoader;
  SandboxAgent: DurableObjectNamespace;
  MCP_OBJECT: DurableObjectNamespace;   // alias for SandboxAgent — required by OAuthProvider
  STORAGE?: R2Bucket;
  USER_REGISTRY: KVNamespace;
  OAUTH_KV: KVNamespace;
  WORKSPACE_DB: D1Database;
  // Vars
  PUBLIC_URL: string;
  ALLOWED_EMAIL_DOMAIN: string;
  // Secrets
  ADMIN_SECRET?: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  ACCESS_TOKEN_URL: string;
  ACCESS_AUTHORIZATION_URL: string;
  ACCESS_JWKS_URL: string;
  COOKIE_ENCRYPTION_KEY: string;
}

// ─── GitPrism MCP provider ────────────────────────────────────────────────────

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

const domainProvider = { tools: domainTools } as const;

// ─── SandboxAgent ─────────────────────────────────────────────────────────────
// One DO instance per MCP session.
// User identity comes from this.props.email (set by OAuthProvider after Access login).
// Workspace is backed by D1 and keyed by email — persistent across all sessions.

export class SandboxAgent extends McpAgent<Env, Record<string, never>, Props> {
  server = new McpServer({ name: "ai-sandbox", version: "1.0.0" });

  // D1-backed workspace: keyed by the user's email so files persist across sessions
  get workspace(): Workspace {
    return new Workspace({
      sql: this.env.WORKSPACE_DB as unknown as SqlStorage,
      r2: this.env.STORAGE,
      name: () => this.props?.email ?? "anonymous",
    });
  }

  // ── Legacy /view handler ──────────────────────────────────────────────────
  // Called when old ?session= links route directly to a pre-OAuth DO instance.
  // Those DOs have their workspace in DO-local SQLite (this.ctx.storage.sql),
  // not in D1, so we build a Workspace against the DO's own storage here.
  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/view") {
      const file = url.searchParams.get("file") ?? "/reports/dashboard.html";
      const legacyWorkspace = new Workspace({
        sql: this.ctx.storage.sql,
        r2: this.env.STORAGE,
        name: () => this.name,
      });
      const content = await legacyWorkspace.readFile(file);
      if (content === null) return new Response(`File not found: ${file}`, { status: 404 });
      const ext = file.split(".").pop()?.toLowerCase() ?? "txt";
      return new Response(content, {
        headers: { "Content-Type": CONTENT_TYPES[ext] ?? "text/plain; charset=utf-8" },
      });
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
        "Files written via state.* persist permanently across all your sessions.",
        "The code must be an async arrow function or a block of statements.",
      ].join("\n"),
      { code: z.string().describe("JavaScript to run. Can use state.*, codemode.*, and gitprism.*") },
      async ({ code }) => {
        const ws = this.workspace;
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(ws)),
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
        "Prefer run_code for simple tasks — it's much faster.",
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
            "src/entry.ts": Object.keys(packages ?? {}).map(p => `import "${p}";`).join("\n") || "export {}",
            ...(packages ? { "package.json": JSON.stringify({ dependencies: packages }) } : {}),
          },
        });
        const ws = this.workspace;
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null, modules: bundledModules as Record<string, string> });
        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(ws)),
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
        "The URL is stable — tied to your identity, not the current session.",
      ].join("\n"),
      { file: z.string().default("/reports/dashboard.html").describe("Workspace path, e.g. /reports/dashboard.html") },
      async ({ file }) => {
        const base  = this.env.PUBLIC_URL.replace(/\/$/, "");
        const email = this.props?.email ?? "anonymous";
        const url   = `${base}/view?user=${encodeURIComponent(email)}&file=${encodeURIComponent(file)}`;
        return { content: [{ type: "text" as const, text: url }] };
      }
    );
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────
//
// OAuthProvider wraps McpAgent.serve() — the official Cloudflare pattern.
// McpAgent.serve() handles ALL MCP transport concerns internally.
// OAuthProvider handles the /authorize, /callback, /token, /register endpoints.
// handleRequest handles /admin, /admin/api/*, and /view.
//
// User setup for OpenCode:
//
//   opencode.jsonc:
//   {
//     "mcp": {
//       "ai-sandbox": { "type": "remote", "url": "https://ai-sandbox.cloudemo.org/mcp" }
//     }
//   }
//
//   First time: opencode mcp auth ai-sandbox
//   → browser opens → Cloudflare Access login → done forever.
//
// Dashboard setup (one-time):
//   1. wrangler kv namespace create OAUTH_KV   → update id in wrangler.jsonc
//   2. wrangler d1 create sandbox-workspaces   → update id in wrangler.jsonc
//   3. Zero Trust → Access → Applications → Add SaaS → OIDC
//      Redirect URL: https://ai-sandbox.cloudemo.org/callback
//      Note Client ID, Secret, and endpoint URLs
//   4. wrangler secret put ACCESS_CLIENT_ID / ACCESS_CLIENT_SECRET /
//      ACCESS_TOKEN_URL / ACCESS_AUTHORIZATION_URL / ACCESS_JWKS_URL /
//      COOKIE_ENCRYPTION_KEY / ADMIN_SECRET

export default new OAuthProvider({
  apiHandler: SandboxAgent.serve("/mcp"),
  apiRoute: "/mcp",
  authorizeEndpoint: "/authorize",
  clientRegistrationEndpoint: "/register",
  defaultHandler: { fetch: handleRequest as unknown as ExportedHandlerFetchHandler<Env> },
  tokenEndpoint: "/token",
});
