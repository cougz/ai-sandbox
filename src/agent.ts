import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Re-export Sandbox DO class — required for the container Durable Object binding
export { Sandbox } from "@cloudflare/sandbox";

// Re-export ChatSession DO — required for the CHAT_SESSION Durable Object binding
export { ChatSession } from "./chat-session";

import { McpAgent } from "agents/mcp";
import { DynamicWorkerExecutor, resolveProvider } from "@cloudflare/codemode";
import { Workspace } from "@cloudflare/shell";
import { stateTools } from "@cloudflare/shell/workers";
import { createWorker } from "@cloudflare/worker-bundler";
import { z } from "zod";
import { domainTools } from "./tools/example";
import { handleRequest, emailToNamespace, SHARED_NAMESPACE, writeLog } from "./access-handler";
import { buildBuiltinToolDefs } from "./tool-defs";
import type { Props } from "./workers-oauth-utils";

// ─── Env ──────────────────────────────────────────────────────────────────────
// Extends the auto-generated Cloudflare.Env (worker-configuration.d.ts) so that
// binding types (DO generics, KV, R2, etc.) are always kept in sync with wrangler.jsonc.
// Only additions not emitted by `wrangler types` are declared here.

export interface Env extends Cloudflare.Env {
  // Container-backed DO — not emitted by `wrangler types` (class re-exported from @cloudflare/sandbox)
  Sandbox: DurableObjectNamespace;
  // ChatSession DO — manages OpenCode lifecycle per user for /chat
  CHAT_SESSION: DurableObjectNamespace;
  // Workers AI binding — used by /chat/ai/v1/* proxy (env.AI.run())
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  AI: any;
  // AUD tag of the /chat CF Access self-hosted application (set in wrangler.jsonc vars)
  CHAT_AUD: string;
  // Runtime secrets — set via `wrangler secret put`, not in wrangler.jsonc bindings
  ADMIN_EMAILS: string;
  ADMIN_SECRET: string;
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

const domainProvider = { tools: domainTools } as const;

// ─── Built-in Tool Registry (served to admin panel via DO /internal/tools) ───
// Single source of truth lives in ./tool-defs.ts — both agent.ts and
// access-handler.ts derive their copies from the same function.

export const BUILTIN_TOOL_DEFS = buildBuiltinToolDefs(Object.keys(domainTools));

// Quick lookup so runtime tool registrations reuse the canonical description.
const toolDesc = Object.fromEntries(BUILTIN_TOOL_DEFS.map(t => [t.name, t.description]));

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
  // @ts-ignore — @modelcontextprotocol/sdk ships two structurally-identical McpServer
  // declarations (top-level 1.28 vs agents-bundled 1.29); the types differ only in a
  // private field name, so the cast is safe at runtime.
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
  private makeProviders(ws: Workspace) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const sharedProvider = Object.assign({}, stateTools(this.sharedWorkspace), { name: "shared" }) as any;
    return [
      resolveProvider(stateTools(ws)),
      resolveProvider(sharedProvider),
      resolveProvider(domainProvider),
    ];
  }

  // Log a tool invocation to the KV ring-buffer (same store as /api/logs).
  private logTool(toolName: string): void {
    writeLog(this.env, this.ctx, "info", "tool.call", {
      tool: toolName,
      user: this.props?.email ?? "anonymous",
    });
  }

  // Register a single user-defined tool on the MCP server.
  // Called both from loadUserTools() at init and from tool_create at runtime.
  registerUserTool(def: UserToolDef) {
    const zodSchema = buildZodSchema(def.schema);
    const handler = async (args: Record<string, unknown>) => {
      this.logTool(def.name);
      const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
      const { result, logs, error } = await executor.execute(
        `(${def.code})(${JSON.stringify(args)})`,
        this.makeProviders(this.workspace),
      );
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }],
      };
    };

    // If the tool is already registered (e.g. from a previous loadUserTools call),
    // update its handler and description in place rather than throwing a duplicate error.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing = (this.server as any)._registeredTools?.[def.name];
    if (existing) {
      existing.update({ callback: handler, description: `[custom] ${def.description}` });
      return;
    }

    this.server.tool(
      def.name,
      `[custom] ${def.description}`,
      zodSchema,
      handler,
    );
  }

  // ── Internal admin endpoint: /internal/tools ─────────────────────────────
  // Called by the admin API (GET /admin/api/tools) via a DO stub.
  // Returns built-in tool definitions + custom tools from the shared workspace.
  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/internal/tools" && request.method === "GET") {
      if (!this.env.ADMIN_SECRET || request.headers.get("X-Admin-Key") !== this.env.ADMIN_SECRET) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json" },
        });
      }
      const sharedWs = makeAgentWorkspace(this.env.WORKSPACE_DB, SHARED_NAMESPACE, this.env.STORAGE, "shared");
      let customTools: unknown[] = [];
      try {
        const entries = await sharedWs.glob("/tools/**") as Array<{ path: string; type: string }>;
        const dir  = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\/tool\.json$/.test(e.path));
        const flat = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\.json$/.test(e.path));
        const seen = new Set<string>();
        const loaded: unknown[] = [];
        for (const entry of [...dir, ...flat]) {
          const m = entry.path.match(/^\/tools\/([^/]+)(?:\/tool)?\.json$/);
          if (!m || seen.has(m[1])) continue;
          const raw = await sharedWs.readFile(entry.path);
          if (!raw) continue;
          try {
            const def = JSON.parse(raw);
            // Attach supporting files for directory-format tools
            if (/^\/tools\/[^/]+\/tool\.json$/.test(entry.path)) {
              const toolDir = entry.path.replace("/tool.json", "");
              def._files = entries
                .filter(e => e.type === "file" && e.path.startsWith(toolDir + "/") && e.path !== entry.path)
                .map(e => e.path);
            }
            loaded.push(def);
            seen.add(m[1]);
          } catch { /* skip malformed */ }
        }
        customTools = loaded;
      } catch { /* shared workspace may be empty */ }
      return new Response(JSON.stringify({ builtin: BUILTIN_TOOL_DEFS, custom: customTools }), {
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }

  // Scan /tools/ for tool definitions, supporting two layouts:
  //   Flat:      /tools/{name}.json        — legacy / simple tools
  //   Directory: /tools/{name}/tool.json   — new standard (tool + assets in one dir)
  // Directory format takes precedence if both exist for the same name.
  // Global tools (shared workspace) are loaded first; personal tools load second
  // and can override a global tool with the same name.
  async loadUserTools() {
    const loadFrom = async (ws: Workspace) => {
      let entries: Array<{ path: string; type: string }> = [];
      try { entries = await ws.glob("/tools/**") as Array<{ path: string; type: string }>; }
      catch { return; }

      const dirEntries  = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\/tool\.json$/.test(e.path));
      const flatEntries = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\.json$/.test(e.path));
      const seen = new Set<string>();

      for (const entry of [...dirEntries, ...flatEntries]) {
        const m = entry.path.match(/^\/tools\/([^/]+)(?:\/tool)?\.json$/);
        if (!m || seen.has(m[1])) continue;
        try {
          const content = await ws.readFile(entry.path);
          if (!content) continue;
          const def: UserToolDef = JSON.parse(content);
          if (def.name && def.description && def.code) {
            this.registerUserTool(def);
            seen.add(m[1]);
          }
        } catch { /* skip malformed */ }
      }
    };
    await loadFrom(this.sharedWorkspace); // global first (lower priority)
    await loadFrom(this.workspace);       // personal second (can override global)
  }

  async init() {
    // All tool descriptions come from the single source of truth in tool-defs.ts
    // via the module-level `toolDesc` lookup.  Zod param descriptions are kept
    // in sync with the canonical params defined there.

    // ── run_code ──────────────────────────────────────────────────────────────
    this.server.tool(
      "run_code",
      toolDesc["run_code"],
      { code: z.string().describe("JavaScript to run. Can use state.*, shared.*, and codemode.*") },
      async ({ code }) => {
        this.logTool("run_code");
        const executor = new DynamicWorkerExecutor({ loader: this.env.LOADER, globalOutbound: null });
        const { result, logs, error } = await executor.execute(code, this.makeProviders(this.workspace));
        return { content: [{ type: "text" as const, text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2) }] };
      }
    );

    // ── run_bundled_code ──────────────────────────────────────────────────────
    this.server.tool(
      "run_bundled_code",
      toolDesc["run_bundled_code"],
      {
        code: z.string().describe("JavaScript to run. Use dynamic import() to load declared packages."),
        packages: z.record(z.string()).optional().describe(
          'Map of npm package names to semver ranges, e.g. { "lodash": "^4.17.0", "date-fns": "*" }. Keys are package names, values are version ranges.'
        ),
      },
      async ({ code, packages }) => {
        this.logTool("run_bundled_code");
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

    // ── get_url ──────────────────────────────────────────────────────────────
    this.server.tool(
      "get_url",
      toolDesc["get_url"],
      {
        file: z.string().describe("Workspace path, e.g. /reports/sales-q4.html"),
        shared: z.boolean().default(false).describe("true = shared workspace, false = personal (default)"),
      },
      async ({ file, shared }) => {
        this.logTool("get_url");
        const base = this.env.PUBLIC_URL.replace(/\/$/, "");
        const url = shared
          ? `${base}/view?shared=true&file=${encodeURIComponent(file)}`
          : `${base}/view?user=${encodeURIComponent(this.props?.email ?? "anonymous")}&file=${encodeURIComponent(file)}`;
        return { content: [{ type: "text" as const, text: url }] };
      }
    );

    // ── tool_create ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_create",
      toolDesc["tool_create"],
      {
        name:        z.string().regex(/^[a-z][a-z0-9_]*$/).describe("Tool name — lowercase letters, digits, and underscores only"),
        description: z.string().describe("What the tool does — shown to the AI in every session"),
        schema:      z.record(z.object({
          type:        z.enum(["string", "number", "boolean", "array", "object"]),
          description: z.string().optional(),
          optional:    z.boolean().optional(),
        })).optional().describe("Parameter schema — omit or pass {} for tools with no arguments"),
        code: z.string().describe("Async arrow function, e.g. async ({ arg1, arg2 }) => { ... }"),
        global: z.boolean().optional().describe("Save to shared workspace (visible to all users) — default false (personal workspace)"),
      },
      async ({ name, description, schema, code, global }) => {
        this.logTool("tool_create");
        const def: UserToolDef = { name, description, schema: schema ?? {}, code };
        const path = `/tools/${name}/tool.json`;
        const targetWs = global ? this.sharedWorkspace : this.workspace;
        await targetWs.writeFile(path, JSON.stringify(def, null, 2));
        this.registerUserTool(def);
        const location = global ? "Shared Workspace (global)" : "Personal Workspace";
        return {
          content: [{ type: "text" as const, text: `Tool '${name}' saved to ${path} in ${location} and registered in this session.` }],
        };
      }
    );

    // ── tool_list ─────────────────────────────────────────────────────────────
    this.server.tool(
      "tool_list",
      toolDesc["tool_list"],
      {},
      async () => {
        this.logTool("tool_list");
        const builtIn = [
          "run_code", "run_bundled_code",
          "get_url",
          "tool_create", "tool_list", "tool_delete", "tool_reload",
          "workspace_import", "workspace_export",
        ];
        const readTools = async (ws: Workspace): Promise<Array<{ name: string; description: string; path: string }>> => {
          const out: Array<{ name: string; description: string; path: string }> = [];
          try {
            const entries = await ws.glob("/tools/**") as Array<{ path: string; type: string }>;
            const dir  = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\/tool\.json$/.test(e.path));
            const flat = entries.filter(e => e.type === "file" && /^\/tools\/[^/]+\.json$/.test(e.path));
            const seen = new Set<string>();
            for (const entry of [...dir, ...flat]) {
              const m = entry.path.match(/^\/tools\/([^/]+)(?:\/tool)?\.json$/);
              if (!m || seen.has(m[1])) continue;
              try {
                const content = await ws.readFile(entry.path);
                if (!content) continue;
                const def: UserToolDef = JSON.parse(content);
                out.push({ name: def.name, description: def.description, path: entry.path });
                seen.add(m[1]);
              } catch { /* skip */ }
            }
          } catch { /* no /tools dir */ }
          return out;
        };
        const [global, personal] = await Promise.all([
          readTools(this.sharedWorkspace),
          readTools(this.workspace),
        ]);
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ builtIn, global, personal }, null, 2) }],
        };
      }
    );

    // ── tool_delete ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_delete",
      toolDesc["tool_delete"],
      { name: z.string().describe("Name of the custom tool to delete") },
      async ({ name }) => {
        this.logTool("tool_delete");
        const paths = [`/tools/${name}/tool.json`, `/tools/${name}.json`];
        for (const p of paths) {
          try {
            await this.workspace.rm(p);
            return { content: [{ type: "text" as const, text: `Tool '${name}' deleted (${p}). It will not load in future sessions.` }] };
          } catch { /* try next */ }
        }
        return { content: [{ type: "text" as const, text: `Tool '${name}' not found in /tools/.` }] };
      }
    );

    // ── tool_reload ───────────────────────────────────────────────────────────
    this.server.tool(
      "tool_reload",
      toolDesc["tool_reload"],
      {},
      async () => {
        this.logTool("tool_reload");
        await this.loadUserTools();
        return { content: [{ type: "text" as const, text: "Custom tools reloaded from shared and personal /tools/ workspaces." }] };
      }
    );

    // ── workspace_import ──────────────────────────────────────────────────────
    // Writes data directly to a workspace file without the content appearing in
    // the tool's return value.  This halves context usage for large payloads:
    // the data enters the LLM context once (as the tool parameter) but the
    // response is a tiny metadata object, not the full content echoed back.
    this.server.tool(
      "workspace_import",
      toolDesc["workspace_import"],
      {
        content: z.string().describe("The data to write — any string content (JSON, CSV, HTML, plain text, etc.)"),
        path: z.string().describe("Destination path in the workspace, e.g. '/data/salesforce-response.json'"),
        shared: z.boolean().default(false).describe("true = write to shared workspace, false = personal workspace (default)"),
        parse_salesforce_aura: z.boolean().default(false).describe(
          "If true, treats content as a raw Salesforce Aura/Lightning runReport response and extracts " +
          "certification records automatically. The parsed records array is written as JSON to the destination path. " +
          "Use this when importing Chrome DevTools network responses from Salesforce report pages."
        ),
      },
      async ({ content, path, shared, parse_salesforce_aura }) => {
        this.logTool("workspace_import");
        const targetWs = shared ? this.sharedWorkspace : this.workspace;
        let bytesWritten = 0;
        let recordCount: number | undefined;

        try {
          if (parse_salesforce_aura) {
            // Parse Salesforce Aura runReport response → extract certification records
            // Handles the common pattern: Chrome DevTools captured network response → workspace file
            const cleaned = content.split("\n").map(line => {
              const m = line.match(/^(\d+):\s(.*)/);
              return m ? m[2] : line;
            }).join("\n");

            const data = JSON.parse(cleaned);

            // Navigate the Aura response structure to find the factMap
            let factMap: Record<string, { rows?: Array<{ dataCells?: Array<{ label?: string }> }> }>;
            if (data?.actions?.[0]?.returnValue?.factMap) {
              factMap = data.actions[0].returnValue.factMap;
            } else if (data?.factMap) {
              factMap = data.factMap;
            } else {
              return {
                content: [{ type: "text" as const, text: JSON.stringify({
                  status: "error",
                  error: "salesforce_parse_failed",
                  message: "Could not find factMap in the Salesforce response. Expected structure: { actions[0].returnValue.factMap } or { factMap }.",
                }, null, 2) }],
              };
            }

            const records: Array<Record<string, string>> = [];
            for (const value of Object.values(factMap)) {
              if (value.rows) {
                for (const row of value.rows) {
                  if (row.dataCells && row.dataCells.length >= 4) {
                    records.push({
                      contact_name: row.dataCells[0]?.label ?? "",
                      certification_name: row.dataCells[1]?.label ?? "",
                      certification_type: row.dataCells[2]?.label ?? "",
                      date_expired: row.dataCells[3]?.label ?? "",
                      cert_type_new: row.dataCells[4]?.label ?? "Other",
                    });
                  }
                }
              }
            }

            const json = JSON.stringify(records, null, 2);
            await targetWs.writeFile(path, json);
            bytesWritten = json.length;
            recordCount = records.length;
          } else {
            // Direct write — no transformation
            await targetWs.writeFile(path, content);
            bytesWritten = content.length;
          }

          const result: Record<string, unknown> = {
            status: "ok",
            path,
            workspace: shared ? "shared" : "personal",
            bytes: bytesWritten,
            message: `Data written to ${path} (${bytesWritten.toLocaleString()} bytes).`,
          };
          if (recordCount !== undefined) {
            result.records_extracted = recordCount;
            result.message = `Salesforce data parsed: ${recordCount} records extracted and saved to ${path} (${bytesWritten.toLocaleString()} bytes).`;
          }

          return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return {
            content: [{ type: "text" as const, text: JSON.stringify({
              status: "error",
              error: "write_failed",
              path,
              message: `Failed to write to workspace: ${msg}`,
            }, null, 2) }],
          };
        }
      }
    );

    // ── workspace_export ──────────────────────────────────────────────────────
    // Reads a file from the workspace and returns its content.
    // Useful when other MCP tools need workspace data without run_code.
    this.server.tool(
      "workspace_export",
      toolDesc["workspace_export"],
      {
        path: z.string().describe("Source path in the workspace, e.g. '/data/salesforce-response.json'"),
        shared: z.boolean().default(false).describe("true = read from shared workspace, false = personal workspace (default)"),
      },
      async ({ path, shared }) => {
        this.logTool("workspace_export");
        const targetWs = shared ? this.sharedWorkspace : this.workspace;
        try {
          const data = await targetWs.readFile(path);
          if (data === null || data === undefined) {
            return {
              content: [{ type: "text" as const, text: JSON.stringify({
                status: "error",
                error: "not_found",
                path,
                message: `File not found: ${path}`,
              }, null, 2) }],
            };
          }
          return {
            content: [{ type: "text" as const, text: JSON.stringify({
              status: "ok",
              path,
              workspace: shared ? "shared" : "personal",
              bytes: data.length,
              content: data,
            }, null, 2) }],
          };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return {
            content: [{ type: "text" as const, text: JSON.stringify({
              status: "error",
              error: "read_failed",
              path,
              message: `Failed to read from workspace: ${msg}`,
            }, null, 2) }],
          };
        }
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
