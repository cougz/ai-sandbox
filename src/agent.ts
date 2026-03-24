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

// ─── Env ─────────────────────────────────────────────────────────────────────

export interface Env {
  LOADER: WorkerLoader;
  SandboxAgent: DurableObjectNamespace;
  STORAGE?: R2Bucket;
}

// ─── Domain tool provider ────────────────────────────────────────────────────

const domainProvider = {
  tools: domainTools,
} as const;

// ─── GitPrism provider ───────────────────────────────────────────────────────
// Calls the GitPrism MCP server via the MCP SDK Client.
// Runs on the HOST (can make outbound HTTP), not inside the sandbox.
// The sandbox calls gitprism.ingest_repo({ url, detail }) via Workers RPC.
//
// We create a fresh Client per call because GitPrism is stateless — there is
// no persistent session to maintain across Durable Object invocations.

function makeGitprismProvider() {
  return {
    name: "gitprism",
    tools: {
      ingest_repo: {
        description: [
          "Convert any public GitHub repository into LLM-ready Markdown.",
          "Args: { url: string (GitHub URL or owner/repo shorthand),",
          "        detail?: 'summary' | 'structure' | 'file-list' | 'full' (default: 'full') }",
          "detail levels:",
          "  summary    — YAML front-matter: repo name, ref, file count, total size",
          "  structure  — summary + ASCII directory tree",
          "  file-list  — structure + table of every file with size and line count",
          "  full       — everything above + complete file contents",
        ].join("\n"),
        execute: async (args: unknown) => {
          const { url, detail = "full" } = args as { url: string; detail?: string };
          const client = new Client({ name: "ai-sandbox", version: "1.0.0" });
          const transport = new StreamableHTTPClientTransport(
            new URL("https://gitprism.cloudemo.org/mcp")
          );
          await client.connect(transport);
          try {
            const result = await client.callTool({
              name: "ingest_repo",
              arguments: { url, detail },
            });
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

// ─── SandboxAgent ─────────────────────────────────────────────────────────────

export class SandboxAgent extends McpAgent<Env, Record<string, never>, {}> {
  server = new McpServer({ name: "ai-sandbox", version: "1.0.0" });

  workspace = new Workspace({
    sql: this.ctx.storage.sql,
    r2: this.env.STORAGE,
    name: () => this.name,
  });

  async init() {
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
          globalOutbound: null,
        });

        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          resolveProvider(makeGitprismProvider()),
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

    this.server.tool(
      "run_bundled_code",
      [
        "Like run_code, but installs npm packages at runtime so the sandbox can import them.",
        "Prefer run_code for tasks that don't need external packages — it's much faster.",
        "",
        "The bundled modules are injected into the sandbox. Use dynamic import():",
        "  const { chunk } = await import('lodash');",
        "",
        "state.*, codemode.*, and gitprism.* are available exactly as in run_code.",
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
        const { modules: bundledModules } = await createWorker({
          files: {
            "src/entry.ts": Object.keys(packages ?? {})
              .map((p) => `import "${p}";`)
              .join("\n") || "export {}",
            ...(packages
              ? { "package.json": JSON.stringify({ dependencies: packages }) }
              : {}),
          },
        });

        const executor = new DynamicWorkerExecutor({
          loader: this.env.LOADER,
          globalOutbound: null,
          modules: bundledModules as Record<string, string>,
        });

        const { result, logs, error } = await executor.execute(code, [
          resolveProvider(stateTools(this.workspace)),
          resolveProvider(domainProvider),
          resolveProvider(makeGitprismProvider()),
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

export default SandboxAgent.serve("/mcp", { binding: "SandboxAgent" });
