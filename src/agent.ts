import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { DynamicWorkerExecutor, resolveProvider } from "@cloudflare/codemode";
import { Workspace } from "@cloudflare/shell";
import { stateTools } from "@cloudflare/shell/workers";
import { createWorker } from "@cloudflare/worker-bundler";
import { z } from "zod";
import { domainTools } from "./tools/example";

// ─── Env ─────────────────────────────────────────────────────────────────────
// Run `npm run types` after editing wrangler.jsonc to regenerate this from
// the generated worker-configuration.d.ts instead.

export interface Env {
  // Dynamic Worker Loader — required (Workers paid plan)
  LOADER: WorkerLoader;
  // Durable Object binding — self-referential, managed by wrangler
  SandboxAgent: DurableObjectNamespace;
  // R2 for large file spill-over. Remove if you don't need persistent large files.
  STORAGE?: R2Bucket;
}

// ─── Domain tool provider ────────────────────────────────────────────────────
// Wrap domainTools as a ToolProvider for the codemode executor.
// The sandbox accesses these as `codemode.toolName({ ...args })`.
// Add/remove tools in src/tools/example.ts (or replace the file entirely).

// Convert an AI SDK-style tool map (from this.mcp.getTools()) into a plain
// ToolProvider that @cloudflare/codemode can resolve without the `ai` peer dep.
function mcpToProvider(tools: Record<string, any>, name: string) {
  return {
    name,
    tools: Object.fromEntries(
      Object.entries(tools)
        .filter(([, t]) => typeof t.execute === "function")
        .map(([toolName, t]) => [
          toolName,
          {
            description: (t.description as string) ?? toolName,
            execute: (args: unknown) => t.execute(args, {}),
          },
        ])
    ),
  };
}

const domainProvider = {
  // name defaults to "codemode" — the LLM calls codemode.kvGet({ key: "..." })
  tools: domainTools,
} as const;

// ─── SandboxAgent ─────────────────────────────────────────────────────────────
// One Durable Object instance per MCP session.
//
// Each instance has:
//   - Its own isolated SQLite workspace (via @cloudflare/shell Workspace)
//   - Access to the Dynamic Worker Loader for spinning up sandboxes
//   - Two MCP tools: run_code and run_bundled_code
//
// OpenCode connects to this as a remote MCP server. Each chat session
// that uses the sandbox gets its own isolated file system automatically.

export class SandboxAgent extends McpAgent<Env, Record<string, never>, {}> {
  server = new McpServer({ name: "ai-sandbox", version: "1.0.0" });

  // Persistent, per-session filesystem backed by the DO's SQLite + optional R2.
  // Files survive across multiple run_code calls within the same session.
  workspace = new Workspace({
    sql: this.ctx.storage.sql,
    r2: this.env.STORAGE,
    name: () => this.name,
  });

  async init() {
    // ── Connect to GitPrism MCP server ───────────────────────────────────────
    // GitPrism converts any public GitHub repo to LLM-ready Markdown.
    // Connecting here makes its tools available inside the sandbox as gitprism.*
    //
    // Auth note: GitPrism uses a server-side GITHUB_TOKEN — no OAuth needed
    // from our side. The token lives on their Worker; we just call the MCP endpoint.
    await this.addMcpServer("gitprism", "https://gitprism.cloudemo.org/mcp", {
      transport: { type: "streamable-http" },
    });

    // ── Tool: run_code ───────────────────────────────────────────────────────
    // The primary tool. Runs a JavaScript snippet in an isolated Dynamic Worker.
    //
    // Inside the sandbox, three namespaces are available:
    //
    //   state.*     — full filesystem (read/write/search/replace/diff/glob...)
    //                 Backed by this session's persistent Workspace.
    //
    //   codemode.*  — your TypeScript RPC tools (src/tools/example.ts)
    //                 Runs in the HOST worker, not the sandbox.
    //
    //   gitprism.*  — GitPrism MCP tools, proxied through the host Worker.
    //                 e.g. gitprism.ingest_repo({ url: "owner/repo", detail: "summary" })
    //
    // Network access is blocked by default (globalOutbound: null).
    // MCP tool calls cross the sandbox boundary via Workers RPC — they are NOT
    // outbound HTTP from inside the sandbox. The host Worker makes those calls.

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
        "Files written via state.* persist across multiple run_code calls in the",
        "same session. Use them to accumulate context or checkpoint work.",
        "",
        "The code must be an async arrow function or a block of statements.",
        "Its return value is JSON-serialized and returned as the tool result.",
      ].join("\n"),
      { code: z.string().describe("JavaScript to run. Can use state.*, codemode.*, and gitprism.*") },
      async ({ code }) => {
        const executor = new DynamicWorkerExecutor({
          loader: this.env.LOADER,
          globalOutbound: null, // fully isolated — no outbound network
        });

        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          // GitPrism MCP tools under the "gitprism" namespace.
          // execute() functions run on the HOST (can make outbound calls),
          // not inside the sandbox.
          resolveProvider(mcpToProvider(this.mcp.getTools(), "gitprism")),
        ]);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2),
            },
          ],
        };
      }
    );

    // ── Tool: run_bundled_code ───────────────────────────────────────────────
    // Like run_code, but first bundles specified npm packages so the sandbox
    // can import them. Slower than run_code (bundles at runtime via npmjs.org).
    //
    // The bundled modules are injected into the sandbox as importable modules.
    // state.* and codemode.* tools are still available.
    //
    // Example usage by the LLM:
    //
    //   run_bundled_code({
    //     packages: { "lodash": "^4", "date-fns": "^3" },
    //     code: `
    //       async () => {
    //         const { chunk } = await import("lodash");
    //         const { format } = await import("date-fns");
    //         const arr = [1,2,3,4,5];
    //         return chunk(arr, 2).map(c => format(new Date(), "'chunk-'dd") + c);
    //       }
    //     `
    //   })

    this.server.tool(
      "run_bundled_code",
      [
        "Like run_code, but installs npm packages at runtime so the sandbox can import them.",
        "Prefer run_code for tasks that don't need external packages — it's much faster.",
        "",
        "The bundled modules are injected into the sandbox. Use dynamic import():",
        "  const { chunk } = await import('lodash');",
        "",
        "state.* and codemode.* tools are available exactly as in run_code.",
      ].join("\n"),
      {
        code: z.string().describe(
          "JavaScript to run. Use dynamic import() to load declared packages."
        ),
        packages: z
          .record(z.string())
          .optional()
          .describe(
            "npm packages to install: { packageName: versionRange }. E.g. { lodash: '^4' }"
          ),
      },
      async ({ code, packages }) => {
        // Bundle the requested packages into a module map
        const { modules: bundledModules } = await createWorker({
          files: {
            // Dummy entry — we only care about resolving the declared deps
            "src/entry.ts": Object.keys(packages ?? {})
              .map((p) => `import "${p}";`)
              .join("\n") || "export {}",
            ...(packages
              ? {
                  "package.json": JSON.stringify({ dependencies: packages }),
                }
              : {}),
          },
        });

        const executor = new DynamicWorkerExecutor({
          loader: this.env.LOADER,
          globalOutbound: null,
          // Inject bundled packages so the sandbox can `await import('...')`
          modules: bundledModules as Record<string, string>,
        });

        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          resolveProvider(mcpToProvider(this.mcp.getTools(), "gitprism")),
        ]);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ result, logs: logs ?? [], error: error ?? null }, null, 2),
            },
          ],
        };
      }
    );
  }
}

// ─── Worker entry point ───────────────────────────────────────────────────────
// Serves the MCP protocol at /mcp.
//
// Add to opencode.jsonc:
//
//   "mcp": {
//     "my-sandbox": {
//       "type": "remote",
//       "url": "https://YOUR_WORKER.YOUR_SUBDOMAIN.workers.dev/mcp"
//     }
//   }
//
// Each OpenCode session automatically gets its own DO instance (isolated
// filesystem, isolated sandbox history). No manual session management needed.

export default SandboxAgent.serve("/mcp", { binding: "SandboxAgent" });
