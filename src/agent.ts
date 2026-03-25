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
import { handleRequest, emailToNamespace, SHARED_NAMESPACE } from "./access-handler";
import type { Props } from "./workers-oauth-utils";

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
  // Secrets
  ADMIN_SECRET?: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  ACCESS_TOKEN_URL: string;
  ACCESS_AUTHORIZATION_URL: string;
  ACCESS_JWKS_URL: string;
  COOKIE_ENCRYPTION_KEY: string;
}

// ─── User-defined tool types ──────────────────────────────────────────────────

type SchemaFieldDef = {
  type: "string" | "number" | "boolean" | "array" | "object";
  description?: string;
  optional?: boolean;
};

interface UserToolDef {
  name: string;
  description: string;
  schema: Record<string, SchemaFieldDef>;
  code: string;
}

// Converts a simple field-map schema into Zod shape for MCP tool registration.
function buildZodSchema(schema: Record<string, SchemaFieldDef>): Record<string, z.ZodTypeAny> {
  const result: Record<string, z.ZodTypeAny> = {};
  for (const [key, def] of Object.entries(schema)) {
    let field: z.ZodTypeAny;
    switch (def.type) {
      case "number":  field = z.number();  break;
      case "boolean": field = z.boolean(); break;
      case "array":   field = z.array(z.unknown()); break;
      case "object":  field = z.record(z.unknown()); break;
      default:        field = z.string();
    }
    if (def.description) field = field.describe(def.description);
    if (def.optional)    field = field.optional() as z.ZodTypeAny;
    result[key] = field;
  }
  return result;
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

// Module-level Workspace cache — mirrors the pattern in access-handler.ts.
// Workspace registers itself in a WeakMap inside @cloudflare/shell and throws if the
// same (sql-source, namespace) pair is constructed twice in one isolate lifetime.
// Keying by the D1 binding object ensures one Workspace per (binding, namespace).
const agentWsCache = new WeakMap<object, Map<string, Workspace>>();

function makeAgentWorkspace(db: D1Database, ns: string, storage: R2Bucket | undefined, displayName: string): Workspace {
  const dbKey = db as unknown as object;
  let byNs = agentWsCache.get(dbKey);
  if (!byNs) { byNs = new Map(); agentWsCache.set(dbKey, byNs); }
  let ws = byNs.get(ns);
  if (!ws) {
    ws = new Workspace({
      sql: db as unknown as SqlStorage,
      namespace: ns,
      r2: storage,
      name: () => displayName,
    });
    byNs.set(ns, ws);
  }
  return ws;
}

export class SandboxAgent extends McpAgent<Env, Record<string, never>, Props> {
  server = new McpServer({ name: "ai-sandbox", version: "1.0.0" });

  // D1-backed workspace: keyed by the user's email so files persist across sessions.
  get workspace(): Workspace {
    const email = this.props?.email ?? "anonymous";
    return makeAgentWorkspace(this.env.WORKSPACE_DB, emailToNamespace(email), this.env.STORAGE, email);
  }

  // Shared team workspace: single fixed namespace readable and writable by all users.
  get sharedWorkspace(): Workspace {
    return makeAgentWorkspace(this.env.WORKSPACE_DB, SHARED_NAMESPACE, this.env.STORAGE, "shared");
  }

  // Build the full provider list for sandbox execution.
  // state.*  → user's personal workspace
  // shared.* → team shared workspace (all users read/write)
  // codemode.* → domain tools
  // gitprism.* → GitHub ingestion
  private makeProviders(ws: Workspace) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sharedProvider = Object.assign({}, stateTools(this.sharedWorkspace), { name: "shared" }) as any;
    return [
      resolveProvider(stateTools(ws)),
      resolveProvider(sharedProvider),
      resolveProvider(domainProvider),
      resolveProvider(makeGitprismProvider()),
    ];
  }

  // Register a single user-defined tool on the MCP server.
  // Called both from loadUserTools() at init and from tool_create at runtime.
  registerUserTool(def: UserToolDef) {
    const zodSchema = buildZodSchema(def.schema);
    this.server.tool(
      def.name,
      `[custom] ${def.description}`,
      zodSchema,
      async (args) => {
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
        const { result, logs, error } = await executor.execute(
          `(${def.code})(${JSON.stringify(args)})`,
          this.makeProviders(this.workspace),
        );
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }],
        };
      },
    );
  }

  // Scan /tools/*.json in the user's workspace and register each as an MCP tool.
  async loadUserTools() {
    let entries: Array<{ path: string; type: string }> = [];
    try {
      entries = await this.workspace.glob("/tools/*.json") as Array<{ path: string; type: string }>;
    } catch { return; }
    for (const entry of entries.filter(e => e.type === "file")) {
      try {
        const content = await this.workspace.readFile(entry.path);
        if (!content) continue;
        const def: UserToolDef = JSON.parse(content);
        if (def.name && def.description && def.code) this.registerUserTool(def);
      } catch { /* skip malformed tool files */ }
    }
  }

  async init() {
    // ── run_code ──────────────────────────────────────────────────────────────
    this.server.tool(
      "run_code",
      [
        "Execute JavaScript code in an isolated V8 sandbox (~2ms startup, no network).",
        "",
        "Available in sandbox:",
        "  state.*     — your personal workspace: readFile, writeFile, glob, searchFiles,",
        "                replaceInFiles, diff, readJson, writeJson, walkTree, ...",
        "  shared.*    — team shared workspace: same API as state.*, readable and writable by all users.",
        "                Use this to access shared templates, configs, and team resources.",
        "  codemode.*  — domain tools: " + Object.keys(domainTools).join(", "),
        "  gitprism.*  — ingest_repo({ url, detail? })",
        "                Converts a public GitHub repo to Markdown.",
        "                detail: 'summary' | 'structure' | 'file-list' | 'full'",
        "",
        "Files written via state.* persist in your personal workspace.",
        "Files written via shared.* are immediately visible to all team members.",
        "The code must be an async arrow function or a block of statements.",
      ].join("\n"),
      { code: z.string().describe("JavaScript to run. Can use state.*, shared.*, codemode.*, and gitprism.*") },
      async ({ code }) => {
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
        const { result, logs, error } = await executor.execute(code, this.makeProviders(this.workspace));
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
        "state.*, shared.*, codemode.*, and gitprism.* are available exactly as in run_code.",
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
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null, modules: bundledModules as Record<string, string> });
        const { result, logs, error } = await executor.execute(code, this.makeProviders(this.workspace));
        return { content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }] };
      }
    );

    // ── get_report_url ────────────────────────────────────────────────────────
    this.server.tool(
      "get_report_url",
      [
        "Get a shareable browser URL for a file written to your personal workspace.",
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

    // ── get_shared_file_url ───────────────────────────────────────────────────
    this.server.tool(
      "get_shared_file_url",
      [
        "Get a shareable browser URL for a file in the team shared workspace.",
        "Use this to share links to team templates or reports stored in the shared workspace.",
        "The URL is stable and accessible to anyone with the link.",
      ].join("\n"),
      { file: z.string().describe("Shared workspace path, e.g. /templates/cf-report.html") },
      async ({ file }) => {
        const base = this.env.PUBLIC_URL.replace(/\/$/, "");
        const url  = `${base}/view?shared=true&file=${encodeURIComponent(file)}`;
        return { content: [{ type: "text" as const, text: url }] };
      }
    );

    // ── tool_create ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_create",
      [
        "Create or update a reusable custom MCP tool in your personal workspace.",
        "The tool is saved to /tools/{name}.json and registered immediately in this session.",
        "It will be auto-loaded at the start of every future session.",
        "",
        "Schema format: { fieldName: { type, description?, optional? } }",
        "  type: 'string' | 'number' | 'boolean' | 'array' | 'object'",
        "",
        "Code: an async arrow function receiving the tool args as an object.",
        "  It has access to state.*, shared.*, codemode.*, gitprism.* — same as run_code.",
        "",
        "Example:",
        "  name: 'render_cf_report'",
        "  description: 'Render data into the Cloudflare HTML report template'",
        "  schema: { title: { type: 'string' }, data: { type: 'object' } }",
        "  code: 'async ({ title, data }) => {",
        "    const tpl = await shared.readFile(\"/templates/cf-report.html\");",
        "    return tpl.replace(\"{{title}}\", title).replace(\"{{data}}\", JSON.stringify(data));",
        "  }'",
      ].join("\n"),
      {
        name:        z.string().regex(/^[a-z][a-z0-9_]*$/).describe("Tool name — lowercase letters, digits, and underscores only"),
        description: z.string().describe("What the tool does — shown to the AI in every session"),
        schema:      z.record(z.object({
          type:        z.enum(["string", "number", "boolean", "array", "object"]),
          description: z.string().optional(),
          optional:    z.boolean().optional(),
        })).optional().describe("Parameter schema — omit or pass {} for tools with no arguments"),
        code: z.string().describe("Async arrow function, e.g. async ({ arg1, arg2 }) => { ... }"),
      },
      async ({ name, description, schema, code }) => {
        const def: UserToolDef = { name, description, schema: schema ?? {}, code };
        await this.workspace.writeFile(`/tools/${name}.json`, JSON.stringify(def, null, 2));
        this.registerUserTool(def);
        return {
          content: [{ type: "text" as const, text: `Tool '${name}' saved to /tools/${name}.json and registered in this session.` }],
        };
      }
    );

    // ── tool_list ─────────────────────────────────────────────────────────────
    this.server.tool(
      "tool_list",
      "List all available MCP tools — built-in tools and your custom tools loaded from /tools/*.json.",
      {},
      async () => {
        const builtIn = [
          "run_code", "run_bundled_code",
          "get_report_url", "get_shared_file_url",
          "tool_create", "tool_list", "tool_delete", "tool_reload",
        ];
        const custom: Array<{ name: string; description: string }> = [];
        try {
          const entries = await this.workspace.glob("/tools/*.json") as Array<{ path: string; type: string }>;
          for (const entry of entries.filter(e => e.type === "file")) {
            try {
              const content = await this.workspace.readFile(entry.path);
              if (!content) continue;
              const def: UserToolDef = JSON.parse(content);
              custom.push({ name: def.name, description: def.description });
            } catch { /* skip */ }
          }
        } catch { /* no /tools dir yet */ }
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ builtIn, custom }, null, 2) }],
        };
      }
    );

    // ── tool_delete ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_delete",
      [
        "Delete a custom tool from your workspace.",
        "The /tools/{name}.json file is removed immediately.",
        "The tool remains callable for the rest of this session but will not load in future sessions.",
      ].join("\n"),
      { name: z.string().describe("Name of the custom tool to delete") },
      async ({ name }) => {
        try {
          await this.workspace.rm(`/tools/${name}.json`);
          return {
            content: [{ type: "text" as const, text: `Tool '${name}' deleted. It will not load in future sessions.` }],
          };
        } catch {
          return { content: [{ type: "text" as const, text: `Tool '${name}' not found in /tools/.` }] };
        }
      }
    );

    // ── tool_reload ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_reload",
      [
        "Reload custom tools from /tools/*.json in your workspace.",
        "Use this after writing tool files manually via run_code to register them",
        "in the current session without starting a new one.",
      ].join("\n"),
      {},
      async () => {
        await this.loadUserTools();
        return { content: [{ type: "text" as const, text: "Custom tools reloaded from /tools/." }] };
      }
    );

    // Auto-load any custom tools the user has saved in their workspace.
    await this.loadUserTools();
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────
//
// OAuthProvider wraps McpAgent.serve() — the official Cloudflare pattern.
// McpAgent.serve() handles ALL MCP transport concerns internally.
// OAuthProvider handles the /authorize, /callback, /token, /register endpoints.
// handleRequest handles /admin, /admin/api/*, /view, and /shared-view.
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
