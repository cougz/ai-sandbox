# AI Sandbox Worker

A multi-user AI agent sandbox deployed on Cloudflare Workers. Exposes an MCP server that lets any MCP-compatible client (OpenCode, Claude Desktop, Cursor, etc.) execute JavaScript in isolated V8 sandboxes, operate on a persistent per-user filesystem, and generate shareable HTML reports — all authenticated via Cloudflare Access.

Built on two of Cloudflare's newest primitives:

- **[Dynamic Workers](https://developers.cloudflare.com/dynamic-workers/)** — spins up a fresh, isolated Worker sandbox on every `run_code` call (~2ms startup). No shared state between executions. Each sandbox gets only the bindings you explicitly pass in.
- **[Code Mode (`@cloudflare/codemode`)](https://developers.cloudflare.com/agents/api-reference/codemode/)** — instead of calling tools one at a time, the LLM writes an async JavaScript function that orchestrates multiple tools with real logic (conditionals, loops, error handling). Code runs inside the Dynamic Worker sandbox; tool calls are dispatched back to the host via Workers RPC.

## Architecture

```
OpenCode / MCP client
        │
        │  MCP over HTTPS (OAuth 2.0)
        ▼
┌─────────────────────────────────────────┐
│          Cloudflare Worker              │
│                                         │
│  OAuthProvider                          │
│  ├── /mcp      → SandboxAgent DO        │
│  ├── /authorize → Cloudflare Access     │
│  ├── /callback  → Access OIDC callback  │
│  ├── /view      → Workspace file server │
│  └── /admin     → Admin dashboard       │
└─────────────────────────────────────────┘
        │
        ├── Durable Object (SandboxAgent) — one per MCP session
        │     └── Dynamic Worker Loader  — isolated V8 sandboxes (via @cloudflare/codemode)
        │
        ├── D1 Database — persistent workspace files per user
        ├── R2 Bucket   — large file spill-over
        ├── KV (OAUTH_KV)     — OAuth tokens & state
        └── KV (USER_REGISTRY) — admin user registry
```

### How Code Mode + Dynamic Workers fit together

```
MCP client sends a natural-language task
        │
        ▼
  SandboxAgent (Durable Object)
        │
        │  LLM writes an async JS function using codemode.* tool calls
        ▼
  DynamicWorkerExecutor (from @cloudflare/codemode)
        │  spins up an isolated Worker via the LOADER binding
        ▼
  ┌─────────────────────────────────────────────┐
  │  Isolated V8 Sandbox (Dynamic Worker)        │
  │                                             │
  │  async () => {                              │
  │    const data = await codemode.kvGet(key)  │
  │    if (data) {                              │
  │      await codemode.kvSet(key, transform)  │
  │    }                                        │
  │    return result                            │
  │  }                                          │
  │                                             │
  │  ✗ No outbound network (globalOutbound:null)│
  │  ✓ codemode.* → Workers RPC → host tools   │
  └─────────────────────────────────────────────┘
        │
        │  Workers RPC (ToolDispatcher)
        ▼
  Host Worker — executes the real tool logic
  (state.*, codemode.*, gitprism.* — full env access)
```

**Key design decisions:**

- `OAuthProvider` (from `@cloudflare/workers-oauth-provider`) wraps `McpAgent.serve()` — the [officially recommended pattern](https://github.com/cloudflare/ai) for authenticated MCP servers on Workers.
- Workspaces are backed by **D1** (not the DO's ephemeral SQLite), so files persist across sessions.
- The `/view` endpoint is **public** — report links can be shared with anyone without requiring login.
- GitPrism (`gitprism.*`) is available in every sandbox via the MCP protocol, requiring no auth from this Worker's side.

---

## Prerequisites

- Cloudflare account on the **Workers Paid plan** (Dynamic Worker Loader requires it)
- Wrangler CLI: `npm install -g wrangler`
- Node.js 18+

---

## One-time infrastructure setup

### 1. KV namespace

`OAUTH_KV` and `USER_REGISTRY` share the existing KV namespace (`670e81fe1d294d50bbf1d1c6e5b9ded3`). Key prefixes don't collide (`oauth:*` vs `user:*`), so no new namespace is needed.

If starting from scratch:

```bash
wrangler kv namespace create USER_REGISTRY
# → outputs an ID; set both OAUTH_KV and USER_REGISTRY to that ID in wrangler.jsonc
```

### 2. Create the D1 workspace database

```bash
wrangler d1 create sandbox-workspaces
# → outputs a database_id, paste it into wrangler.jsonc under WORKSPACE_DB
```

### 3. Create the R2 bucket

```bash
wrangler r2 bucket create sandbox-storage
```

### 4. Update `wrangler.jsonc` with the IDs from steps 1–2

Replace `REPLACE_WITH_OAUTH_KV_ID` and `REPLACE_WITH_D1_ID` with the values printed by the commands above.

---

## Cloudflare Access setup (Zero Trust dashboard)

Authentication uses **Cloudflare Access for SaaS (OIDC)**. This gives you an OAuth server backed by your existing Identity Provider (Google, Okta, etc.) without managing OAuth infrastructure yourself.

### Step 1 — Ensure you have an Identity Provider configured

Zero Trust → Settings → Authentication → Add a provider (e.g. Google).

### Step 2 — Create an Access for SaaS application

Zero Trust → Access → Applications → **Add an application** → **SaaS**

| Field | Value |
|---|---|
| Application name | `AI Sandbox MCP` |
| Application type | `OIDC` |
| Redirect URL | `https://<your-domain>/callback` |
| Scopes | `openid`, `email`, `profile` |

Click **Save**. Note the values on the next screen:

| Secret name | Where to find it |
|---|---|
| `ACCESS_CLIENT_ID` | "Client ID" on the app page |
| `ACCESS_CLIENT_SECRET` | "Client secret" |
| `ACCESS_TOKEN_URL` | "Token endpoint" |
| `ACCESS_AUTHORIZATION_URL` | "Authorization endpoint" |
| `ACCESS_JWKS_URL` | "Key endpoint" |

### Step 3 — Add an Access policy

On the same application, add a policy to restrict which users can authenticate (e.g. by email domain, identity provider group, or specific emails).

---

## Secrets

Set all secrets via Wrangler after deploying:

```bash
# Cloudflare Access for SaaS credentials (from step 2 above)
wrangler secret put ACCESS_CLIENT_ID
wrangler secret put ACCESS_CLIENT_SECRET
wrangler secret put ACCESS_TOKEN_URL
wrangler secret put ACCESS_AUTHORIZATION_URL
wrangler secret put ACCESS_JWKS_URL

# Cookie signing key — any long random string
wrangler secret put COOKIE_ENCRYPTION_KEY
# e.g. openssl rand -hex 32

# Admin dashboard password
wrangler secret put ADMIN_SECRET
# e.g. openssl rand -hex 16
```

---

## Environment variables (`wrangler.jsonc` → `vars`)

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_URL` | `https://ai-sandbox.cloudemo.org` | Base URL used to build shareable `/view` links from `get_report_url`. Update if you use a different domain. |
| `ALLOWED_EMAIL_DOMAIN` | — | Server-side email domain check after Access login. Set to restrict authentication to a specific org (e.g. `@example.com`). |

---

## KV bindings

| Binding | Purpose | Notes |
|---|---|---|
| `OAUTH_KV` | OAuth provider state (client registrations, tokens, auth codes) | Managed automatically by `@cloudflare/workers-oauth-provider` |
| `USER_REGISTRY` | Admin user listing — populated automatically on first login | Keys: `user:{email}` → `{email, name, createdAt}` |

---

## D1 binding

| Binding | Database name | Purpose |
|---|---|---|
| `WORKSPACE_DB` | `sandbox-workspaces` | Persistent workspace files per user (namespaced by email via `@cloudflare/shell`) |

---

## R2 binding

| Binding | Bucket name | Purpose |
|---|---|---|
| `STORAGE` | `sandbox-storage` | Large file spill-over for workspace (files > threshold are stored here automatically) |

---

## Deploy

```bash
npm install
wrangler deploy
```

---

## Connecting OpenCode

Each user adds this to their `opencode.jsonc`:

```jsonc
{
  "mcp": {
    "ai-sandbox": {
      "type": "remote",
      "url": "https://<your-domain>/mcp"
    }
  }
}
```

**First time only** — run the auth flow:

```bash
opencode mcp auth ai-sandbox
```

A browser window opens → Cloudflare Access login → token stored in `~/.local/share/opencode/mcp-auth.json` → all future sessions are automatic.

---

## MCP tools

Once connected, the following tools are available in every session.

### `run_code`

Execute JavaScript in an isolated V8 sandbox powered by **Dynamic Workers** (~2ms startup). No outbound network access from the sandbox — all interaction with the outside world goes through typed `codemode.*` tool calls dispatched via **Workers RPC** back to the host.

Inside the sandbox, the LLM writes an async function using **Code Mode** — it can chain tool calls with real logic rather than issuing them one at a time:

```js
async () => {
  const raw = await codemode.kvGet({ key: "pipeline-data" });
  const parsed = JSON.parse(raw);
  const summary = parsed.runs.filter(r => r.status === "failed");
  await codemode.kvSet({ key: "failures", value: JSON.stringify(summary) });
  return summary.length;
}
```

Available namespaces:

| Namespace | Description |
|---|---|
| `state.*` | Full filesystem: `readFile`, `writeFile`, `glob`, `searchFiles`, `replaceInFiles`, `diff`, `readJson`, `writeJson`, `walkTree`, and more |
| `codemode.*` | Your custom TypeScript RPC tools (edit `src/tools/example.ts`) |
| `gitprism.*` | `ingest_repo({ url, detail? })` — converts any public GitHub repo to Markdown |

Files written via `state.*` persist permanently across all sessions for that user (backed by D1).

### `run_bundled_code`

Same as `run_code` but bundles npm packages at runtime so the sandbox can `import` them. The Dynamic Worker sandbox receives the bundled modules injected as ES modules. Slower — prefer `run_code` for simple tasks.

### `get_report_url`

Returns a stable, shareable URL for any HTML file in the workspace. The link works without login (the `/view` endpoint is public).

---

## Admin dashboard

Visit `https://<your-domain>/admin` and enter your `ADMIN_SECRET`.

Features:
- Lists all users who have authenticated (auto-populated)
- Shows file count per user's workspace
- Expand any user to see individual files, with **View ↗** links for HTML reports
- Wipe a user's entire workspace
- Delete individual files
- Remove a user from the registry (workspace data in D1 is preserved)

---

## Adding domain tools

Edit `src/tools/example.ts` to replace the stub KV tools with calls to your real services (databases, APIs, etc.):

```typescript
export const domainTools = {
  myQuery: {
    description: "Query my database",
    execute: async ({ sql }: { sql: string }) => {
      // This runs in the HOST Worker, not the sandbox.
      // Full access to env bindings, secrets, external APIs.
      return env.MY_D1.prepare(sql).all();
    },
  },
};
```

The LLM calls these as `codemode.myQuery({ sql: "..." })` inside the sandbox via Workers RPC. The sandbox never has direct database access — it only sees return values.

---

## Report generation

Generate reports from the sandbox and get a shareable link:

```
User: "Analyse the pipeline data and create a dashboard"

→ run_code writes /reports/pipeline-dashboard.html
→ get_report_url returns: https://<your-domain>/view?user=alice@example.com&file=/reports/pipeline-dashboard.html
```

The LLM can use any styling approach — write self-contained HTML with inline CSS and Chart.js, or store reusable design tokens in the workspace (e.g. `/templates/base.css`, `/templates/charts.js`) and read them back with `state.readFile` before composing the final report.

---

## Rooms for improvement

### Security

- **JWT verification uses Access JWKS** — currently fetches the JWKS on every callback. Should cache the public key in KV with a reasonable TTL to avoid the extra network round-trip and potential failures.
- **`/view` is fully public** — anyone with a URL can read any workspace file. Consider adding an optional `token` query parameter for sensitive reports, or gating `/view` behind Access with a bypass for specific file types.
- **Admin secret is a plain string header** — replace with Cloudflare Access protecting `/admin` directly (add a second Access Application scoped to your email only).
- **D1 workspace has no per-user isolation at the SQL level** — a bug or exploit in the shell library could theoretically read another user's files. Consider row-level security or separate D1 databases per user.

### Workspace persistence

- **`run_bundled_code` entry point detection is fragile** — the `@cloudflare/worker-bundler` `createWorker` call uses a dummy entry to resolve packages. If the bundler can't find an entry point it returns an error. Needs a more robust approach (e.g. explicit `entryPoint` option once available).
- **Workspace reads/writes in the DO are not transactional** — concurrent `run_code` calls from the same user could produce race conditions in D1. Consider wrapping multi-step workspace operations in a single sandbox execution.
- **No workspace quotas** — a single user could fill D1 with large files. Add a per-user file size limit enforced at the `run_code` tool level.

### Auth & multi-tenancy

- **One DO per MCP session, not per user** — `McpAgent.serve()` creates a fresh DO for each MCP session. The workspace is persistent (D1), but any in-memory state (e.g. caches) resets between sessions. This is correct behaviour but worth being aware of.
- **No token refresh** — OpenCode stores the OAuth token and uses it until it expires. If the Access session TTL is short (< 24h), users will need to re-authenticate. Consider increasing the Access session duration to 7 days for internal tools.
- **No rate limiting** — `run_code` creates a new Dynamic Worker on every call. Add a per-user rate limit via Cloudflare's Rate Limiting binding if you onboard many users.

### Developer experience

- **Domain tools (`codemode.*`) are hardcoded** — every user shares the same set of domain tools. A future improvement would let each user or team define their own tool set, loaded from KV or a separate Worker.
- **No streaming** — `run_code` returns the full result synchronously. For long-running code, consider returning a task ID and polling, or streaming logs via SSE.
- **`run_bundled_code` is slow** — bundles packages at runtime by fetching from the npm registry. Cache the bundled module map in KV keyed by the package manifest hash.
- **GitPrism creates a new MCP client per call** — the `@modelcontextprotocol/sdk` `Client` is stateless (GitPrism is stateless) so this is correct, but it adds connection overhead. Pool or reuse connections if GitPrism adds stateful features.

### Operations

- **No observability** — add `observability: { enabled: true }` to `wrangler.jsonc` and instrument `run_code` calls with timing and error metrics.
- **No workspace TTL** — files live forever. Add a DO Alarm on first write that cleans up workspace files older than N days.
- **Admin dashboard has no pagination** — the `GET /admin/api/users` endpoint returns all users at once. Add cursor-based pagination once the user count grows.
