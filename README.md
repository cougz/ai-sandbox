# AI Sandbox Worker

A multi-user AI agent sandbox deployed on Cloudflare Workers. Exposes an MCP server that lets any MCP-compatible client (OpenCode, Claude Desktop, Cursor, etc.) execute JavaScript in isolated V8 sandboxes, operate on a persistent per-user filesystem, and generate shareable HTML reports - all authenticated via Cloudflare Access.

Built on two of Cloudflare's newest primitives:

- **[Dynamic Workers](https://developers.cloudflare.com/dynamic-workers/)** - spins up a fresh, isolated Worker sandbox on every `run_code` call (~2ms startup). No shared state between executions. Each sandbox gets only the bindings you explicitly pass in.
- **[Code Mode (`@cloudflare/codemode`)](https://developers.cloudflare.com/agents/api-reference/codemode/)** - instead of calling tools one at a time, the LLM writes an async JavaScript function that orchestrates multiple tools with real logic (conditionals, loops, error handling). Code runs inside the Dynamic Worker sandbox; tool calls are dispatched back to the host via Workers RPC.

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [One-time infrastructure setup](#one-time-infrastructure-setup)
- [Cloudflare Access setup](#cloudflare-access-setup-zero-trust-dashboard)
- [Secrets](#secrets)
- [Environment variables](#environment-variables-wranglersonc--vars)
- [Deploy](#deploy)
- [Connecting OpenCode](#connecting-opencode)
- [MCP tools](#mcp-tools)
- [Dashboard](#dashboard-dash)
- [Adding domain tools](#adding-domain-tools)
- [Report generation](#report-generation)
- [Migration from legacy admin panel](#migration-from-legacy-admin-panel)
- [Future Improvements](#future-improvements)

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
│  └── /dash      → Unified dashboard     │
│       ├── Admin view (full access)      │
│       └── User view (limited access)    │
└─────────────────────────────────────────┘
        │
        ├── Durable Object (SandboxAgent) - one per MCP session
        │     └── Dynamic Worker Loader  - isolated V8 sandboxes (via @cloudflare/codemode)
        │
        ├── D1 Database - persistent workspace files per user
        ├── R2 Bucket   - large file spill-over
        ├── KV (OAUTH_KV)     - OAuth tokens & state
        └── KV (USER_REGISTRY) - user registry
```

### Role-Based Access Control

The dashboard (`/dash`) uses **unified authentication via Cloudflare Access** with **role-based authorization**:

- **All users** authenticate through Cloudflare Access (via One-Time PIN or Identity Provider)
- **Role determination** happens server-side by checking the user's email against `ADMIN_EMAILS`
- **Admins** see full dashboard with Users, Tools, Files, Logs, and My Account sections
- **Regular users** see limited dashboard with Tools, Files, and My Account sections
- **Server-side enforcement** - API endpoints return 403 for unauthorized operations

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
   Host Worker - executes the real tool logic
   (state.*, codemode.* - full env access)
```

**Key design decisions:**

- `OAuthProvider` (from `@cloudflare/workers-oauth-provider`) wraps `McpAgent.serve()` - the [officially recommended pattern](https://github.com/cloudflare/ai) for authenticated MCP servers on Workers.
- Workspaces are backed by **D1** (not the DO's ephemeral SQLite), so files persist across sessions.
- The `/view` endpoint is **public** - report links can be shared with anyone without requiring login.
- **Authentication is 100% Cloudflare Access** - no shared secrets, no API keys, role-based access controlled via email allowlist.


---

## Prerequisites

- Cloudflare account on the **Workers Paid plan** (Dynamic Worker Loader requires it)
- Wrangler CLI: `npm install -g wrangler`
- Node.js 18+

---

## One-time infrastructure setup

### 1. KV namespace

`OAUTH_KV` and `USER_REGISTRY` can share a single KV namespace. Key prefixes don't collide (`oauth:*` for OAuth state, `user:*` for user registry), so no new namespace is needed if you already have one.

Create one if starting from scratch:

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

Authentication uses **Cloudflare Access for SaaS (OIDC)**. This gives you an OAuth server backed by your existing Identity Provider (Google, Okta, etc.) or One-Time PIN without managing OAuth infrastructure yourself.

### Step 1 - Configure One-Time PIN (Recommended for testing)

Zero Trust → Settings → Authentication → **Add a provider** → **One-time PIN**

Or use your existing Identity Provider (Google, Okta, Azure AD, etc.).

### Step 2 - Create an Access Application

Zero Trust → Access → Applications → **Add an application** → **Self-hosted**

| Field | Value |
|---|---|
| Application name | `AI Sandbox Dashboard` |
| Subdomain / Domain | `ai-sandbox` (or your domain) |
| Path | `/dash` |

Click **Next**.

### Step 3 - Add an Access Policy

Create an **Allow** policy:

| Setting | Value |
|---|---|
| Policy name | `Allow Cloudflare Users` |
| Action | Allow |
| Include | Emails ending in: `@cloudflare.com` |

Add additional **Include** rules for specific admin emails if they don't match the domain pattern.

Click **Save**.

### Step 4 - Create Access for SaaS application (for MCP OAuth)

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

### Step 5 - Add a policy to the SaaS application

Add the same **Allow** policy as Step 3 (or restrict further as needed).

---

## Secrets

Set secrets via `wrangler secret put <name>` after deploying. All required secrets are listed in the table below.

| Secret | Description |
|---|---|
| `ADMIN_EMAILS` | Comma-separated list of admin email addresses. These users get full dashboard access; all other authenticated users get limited access. |
| `ACCESS_CLIENT_ID` | Cloudflare Access for SaaS - Client ID (from Access for SaaS application setup) |
| `ACCESS_CLIENT_SECRET` | Cloudflare Access for SaaS - Client secret (from Access for SaaS application setup) |
| `ACCESS_TOKEN_URL` | Cloudflare Access for SaaS - Token endpoint (from Access for SaaS application setup) |
| `ACCESS_AUTHORIZATION_URL` | Cloudflare Access for SaaS - Authorization endpoint (from Access for SaaS application setup) |
| `ACCESS_JWKS_URL` | Cloudflare Access for SaaS - JWKS endpoint (from Access for SaaS application setup) |
| `COOKIE_ENCRYPTION_KEY` | Random string for cookie signing (generate with: `openssl rand -hex 32`) |

**Example:**
```bash
# Set each secret interactively
wrangler secret put ADMIN_EMAILS
# Enter: admin1@cloudflare.com,admin2@cloudflare.com

wrangler secret put COOKIE_ENCRYPTION_KEY
# Enter: (output from: openssl rand -hex 32)
```

**Note:** `ADMIN_SECRET` has been removed. Admin access is now controlled entirely via Cloudflare Access + `ADMIN_EMAILS` secret.

---

## Environment variables (`wrangler.jsonc` → `vars`)

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_URL` | `https://ai-sandbox.cloudemo.org` | Base URL used to build shareable `/view` links from `get_url`. Update if you use a different domain. |

---

## KV bindings

| Binding | Purpose | Notes |
|---|---|---|
| `OAUTH_KV` | OAuth provider state (client registrations, tokens, auth codes) | Managed automatically by `@cloudflare/workers-oauth-provider` |
| `USER_REGISTRY` | User listing - populated automatically on first login | Keys: `user:{email}` → `{email, name, createdAt}` |

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

**First time only** - run the auth flow:

```bash
opencode mcp auth ai-sandbox
```

A browser window opens → Cloudflare Access login → token stored in `~/.local/share/opencode/mcp-auth.json` → all future sessions are automatic.

---

## MCP tools

Once connected, the following tools are available in every session.

### `run_code`

Execute JavaScript in an isolated V8 sandbox powered by **Dynamic Workers** (~2ms startup). No outbound network access from the sandbox - all interaction with the outside world goes through typed `codemode.*` tool calls dispatched via **Workers RPC** back to the host.

Inside the sandbox, the LLM writes an async function using **Code Mode** - it can chain tool calls with real logic rather than issuing them one at a time:

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

Files written via `state.*` persist permanently across all sessions for that user (backed by D1).

### `run_bundled_code`

Same as `run_code` but bundles npm packages at runtime so the sandbox can `import` them. The Dynamic Worker sandbox receives the bundled modules injected as ES modules. Slower - prefer `run_code` for simple tasks.

### `get_url`

Returns a stable, shareable URL for any file in the workspace. Defaults to your personal workspace (`state.*`); set `shared=true` for the team shared workspace (`shared.*`). The link works without login (the `/view` endpoint is public).

---

## Dashboard (`/dash`)

Visit `https://<your-domain>/dash` after authenticating via Cloudflare Access.

The dashboard **automatically adapts** based on your role:

### Admin View (email is in `ADMIN_EMAILS`)

**Navigation**: Users | Tools | Files | Logs | My Account

- **Users**: List all authenticated users, provision new users, browse workspaces, wipe workspaces, remove users
- **Tools**: View built-in and custom tools, edit JSON, browse tool directories, delete custom tools
- **Files**: Browse any user's workspace or shared workspace, view/edit/delete files
- **Logs**: View structured Worker events (7-day TTL)
- **My Account**: Personal stats (email, name, first login, file count)

### User View (email not in `ADMIN_EMAILS`)

**Navigation**: Tools | Files | My Account

- **Tools**: View built-in and custom tools (no edit/delete)
- **Files**: Browse your personal workspace only (no other users' workspaces)
- **My Account**: Personal stats (email, name, first login, file count)

### Security Model

- **Authentication**: Handled entirely by Cloudflare Access at the edge
- **Authorization**: Server-side role checking on every request
- **Data isolation**: Backend enforces workspace access; frontend only renders what it receives
- **No secrets in frontend**: Role is never exposed to client-side code

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

The LLM calls these as `codemode.myQuery({ sql: "..." })` inside the sandbox via Workers RPC. The sandbox never has direct database access - it only sees return values.

---

## Report generation

Generate reports from the sandbox and get a shareable link:

```
User: "Analyse the pipeline data and create a dashboard"

→ run_code writes /reports/pipeline-dashboard.html
→ get_url returns: https://<your-domain>/view?user=alice@example.com&file=/reports/pipeline-dashboard.html
```

The LLM can use any styling approach - write self-contained HTML with inline CSS and Chart.js, or store reusable design tokens in the workspace (e.g. `/templates/base.css`, `/templates/charts.js`) and read them back with `state.readFile` before composing the final report.

---

## Future Improvements

See [ROADMAP.md](./ROADMAP.md) for planned enhancements and known limitations.

---

## Migration from legacy admin panel

If you were previously using `/admin` with `ADMIN_SECRET`:

1. **Set `ADMIN_EMAILS`** as a secret: `wrangler secret put ADMIN_EMAILS` (comma-separated emails)
2. **Remove `ADMIN_SECRET`** from Wrangler secrets: `wrangler secret delete ADMIN_SECRET`
3. **Update Access Policy** to protect `/dash` instead of `/admin`
4. **Update bookmarks** from `/admin` to `/dash`

The dashboard will automatically detect your role based on email and show the appropriate interface.
