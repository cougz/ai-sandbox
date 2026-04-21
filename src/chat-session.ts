/**
 * ChatSession Durable Object
 *
 * One instance per user (keyed by email hash).  Manages the OpenCode server
 * lifecycle inside the Cloudflare Container and persists per-user configuration.
 *
 * Key design: ensureServer() fires off startup via ctx.waitUntil() and returns
 * IMMEDIATELY so the Worker is never blocked waiting for OpenCode to boot.
 * The container cold-start + OpenCode startup can take 60-90s; the Worker's
 * RPC timeout would kill a synchronous await long before that.
 *
 * The chat page shows a loading screen and polls /chat/status/{sandboxId} until
 * OpenCode is ready, then mounts the UI.
 */

import { DurableObject } from "cloudflare:workers";
import { getSandbox } from "@cloudflare/sandbox";
import { createOpencodeServer, type OpencodeServer } from "@cloudflare/sandbox/opencode";
import type { Env } from "./agent";

// ─── Constants ────────────────────────────────────────────────────────────────

const OPENCODE_PORT   = 4096;
const WORKSPACE_DIR   = "/home/user/workspace";
const MCP_SERVER_NAME = "ai-sandbox";
const DEFAULT_MODEL   = "@cf/moonshotai/kimi-k2.6";

// ─── Available Workers AI models ─────────────────────────────────────────────

export const AVAILABLE_MODELS: Record<string, string> = {
  "@cf/moonshotai/kimi-k2.6":                      "Kimi K2.6 (default, 262K ctx)",
  "@cf/meta/llama-4-scout-17b-16e-instruct":        "Llama 4 Scout 17B",
  "@cf/meta/llama-3.3-70b-instruct-fp8-fast":       "Llama 3.3 70B",
  "@cf/qwen/qwen3-235b-a22b":                       "Qwen3 235B",
  "@cf/openai/gpt-oss-120b":                        "GPT-OSS 120B",
  "@cf/deepseek-ai/deepseek-r1-distill-llama-70b":  "DeepSeek R1 Distill 70B",
};

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ChatUserConfig {
  model: string;
  mcpServers: Record<string, { url: string; enabled: boolean }>;
}

interface CachedServer {
  server:       OpencodeServer;
  publicOrigin: string;
}

// ─── ChatSession DO ───────────────────────────────────────────────────────────

export class ChatSession extends DurableObject<Env> {
  /** Fully started servers (createOpencodeServer resolved). */
  private servers          = new Map<string, CachedServer>();
  /** Sandbox IDs whose startup is currently in progress. */
  private startupInProgress = new Set<string>();
  private publicOrigins    = new Map<string, string>();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get sandboxNs(): any {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (this.env as any).Sandbox;
  }

  // ── Config ─────────────────────────────────────────────────────────────────

  private buildOptions(publicOrigin: string, sandboxId: string, userConfig: ChatUserConfig) {
    const model = userConfig.model || DEFAULT_MODEL;

    const mcpServers: Record<string, unknown> = {
      [MCP_SERVER_NAME]: {
        type:    "remote",
        url:     `${this.env.PUBLIC_URL}/mcp`,
        enabled: true,
        oauth: {
          redirectUri: `${publicOrigin}/chat/oauth/${sandboxId}/mcp/oauth/callback`,
        },
      },
    };

    for (const [name, cfg] of Object.entries(userConfig.mcpServers || {})) {
      if (name !== MCP_SERVER_NAME) {
        mcpServers[name] = { type: "remote", url: cfg.url, enabled: cfg.enabled };
      }
    }

    return {
      port:      OPENCODE_PORT,
      directory: WORKSPACE_DIR,
      config: {
        model: `openai-compatible/${model}`,
        provider: {
          "openai-compatible": {
            options: {
              baseURL: `${publicOrigin}/chat/ai/v1`,
              apiKey:  "workers-ai",
            },
            models: Object.fromEntries(
              Object.entries(AVAILABLE_MODELS).map(([id, n]) => [id, { name: n }])
            ),
          },
        },
        mcp: mcpServers,
      },
    };
  }

  // ── User config ─────────────────────────────────────────────────────────────

  async getUserConfig(): Promise<ChatUserConfig> {
    const stored = await this.ctx.storage.get<ChatUserConfig>("config");
    return stored ?? { model: DEFAULT_MODEL, mcpServers: {} };
  }

  async updateUserConfig(patch: Partial<ChatUserConfig>): Promise<ChatUserConfig> {
    const current = await this.getUserConfig();
    const updated: ChatUserConfig = {
      model:      patch.model      ?? current.model,
      mcpServers: patch.mcpServers ?? current.mcpServers,
    };
    await this.ctx.storage.put("config", updated);
    return updated;
  }

  // ── Status ──────────────────────────────────────────────────────────────────

  /** Returns "ready" | "starting" | "idle". */
  getStatus(sandboxId: string): "ready" | "starting" | "idle" {
    if (this.servers.has(sandboxId))          return "ready";
    if (this.startupInProgress.has(sandboxId)) return "starting";
    return "idle";
  }

  // ── OpenCode lifecycle ───────────────────────────────────────────────────────

  /**
   * Kick off OpenCode startup and return IMMEDIATELY.
   *
   * createOpencodeServer waits up to 180s for OpenCode to be ready (container
   * cold-start + process startup). That far exceeds the Worker's RPC timeout, so
   * we never await it from the Worker side. Instead we use ctx.waitUntil() to
   * keep the DO alive while the startup runs in the background.
   *
   * Callers poll getStatus() or /chat/status/* to know when ready.
   */
  ensureServer(sandboxId: string, publicOrigin: string): void {
    this.publicOrigins.set(sandboxId, publicOrigin);

    // Already ready or already starting — nothing to do.
    if (this.servers.has(sandboxId) || this.startupInProgress.has(sandboxId)) return;

    this.startupInProgress.add(sandboxId);

    const startup = this._doStart(sandboxId, publicOrigin)
      .then(() => {
        this.startupInProgress.delete(sandboxId);
        console.log(`[ChatSession] OpenCode ready for ${sandboxId}`);
      })
      .catch((err: unknown) => {
        this.startupInProgress.delete(sandboxId);
        console.error(`[ChatSession] OpenCode startup failed for ${sandboxId}:`, String(err));
      });

    // Keep the DO alive until startup resolves.
    this.ctx.waitUntil(startup);
  }

  private async _doStart(sandboxId: string, publicOrigin: string): Promise<void> {
    const userConfig = await this.getUserConfig();
    const options    = this.buildOptions(publicOrigin, sandboxId, userConfig);
    const sandbox    = getSandbox(this.sandboxNs, sandboxId);

    console.log(`[ChatSession] Starting OpenCode for ${sandboxId}...`);
    // createOpencodeServer handles process reuse — safe to call concurrently.
    const server = await createOpencodeServer(sandbox, options);
    this.servers.set(sandboxId, { server, publicOrigin });
  }

  resetInstance(sandboxId: string): void {
    this.servers.delete(sandboxId);
    this.startupInProgress.delete(sandboxId);
  }

  // ── MCP management ──────────────────────────────────────────────────────────

  async getMcpStatuses(sandboxId: string): Promise<Record<string, unknown>> {
    const cached = this.servers.get(sandboxId);
    if (!cached) throw new Error("OpenCode server not started");
    const sandbox = getSandbox(this.sandboxNs, sandboxId);
    const req     = new Request(`${cached.server.url}/mcp`, { method: "GET" });
    const resp: Response = await sandbox.containerFetch(req, cached.server.port);
    if (!resp.ok) throw new Error(`OpenCode MCP status error: ${resp.status}`);
    return resp.json<Record<string, unknown>>();
  }

  async authenticateMcp(sandboxId: string, name: string): Promise<unknown> {
    const cached = this.servers.get(sandboxId);
    if (!cached) throw new Error("OpenCode server not started");
    const sandbox = getSandbox(this.sandboxNs, sandboxId);
    const req = new Request(
      `${cached.server.url}/mcp/${encodeURIComponent(name)}/auth/authenticate`,
      { method: "POST" },
    );
    const resp: Response = await sandbox.containerFetch(req, cached.server.port);
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`MCP auth error for '${name}': ${body}`);
    }
    return resp.json();
  }
}
