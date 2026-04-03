# Roadmap & Rooms for Improvement

## Container Terminal Integration

The `/dash` terminal provides a full Linux container (Python, Node.js, shell), but it's currently isolated from the MCP workflow. The container should become a first-class execution environment for AI agents:

### Phase 1: Workspace ↔ Container Bridge
- Implement `container_upload`, `container_download`, `container_sync` tools to move files between D1/R2 workspace and container filesystem
- Reuse the same container instance between `/dash` terminal and AI agent (deterministic ID from email)

### Phase 2: MCP Container Tools
- `container_exec` - Run shell commands in the container with full Linux/network access
- `container_process_start/list/kill/logs` - Background process management for long-running servers
- `container_preview_url` - Expose container ports as public URLs for live previews
- `container_git_clone` - Clone repos into container for build workflows

### Phase 3: Unified Workflow Documentation
- Update tool descriptions to explain the three-primitive model:
  - **Dynamic Workers** (`run_code`): Fast (~2ms), JS-only, no network, best for data transforms
  - **Container** (`container_*`): Full Linux, any language, network, best for builds/servers
  - **Workspace** (`state.*`/`shared.*`): Persistent D1/R2 storage, source of truth
- Document real-world patterns (Python data pipeline, React app with preview, etc.)

### Phase 4: Live Agent Activity Feed
- Add activity log in dashboard showing AI agent container operations
- Subscribe to container events via SSE endpoint
- Display command output and process status in the `/dash` UI

## Security

- **JWT verification uses Access JWKS** - currently fetches the JWKS on every callback. Should cache the public key in KV with a reasonable TTL to avoid the extra network round-trip and potential failures.
- **`/view` is fully public** - anyone with a URL can read any workspace file. Consider adding an optional `token` query parameter for sensitive reports, or gating `/view` behind Access with a bypass for specific file types.
- **D1 workspace has no per-user isolation at the SQL level** - a bug or exploit in the shell library could theoretically read another user's files. Consider row-level security or separate D1 databases per user.

## Workspace persistence

- **`run_bundled_code` entry point detection is fragile** - the `@cloudflare/worker-bundler` `createWorker` call uses a dummy entry to resolve packages. If the bundler can't find an entry point it returns an error. Needs a more robust approach (e.g. explicit `entryPoint` option once available).
- **Workspace reads/writes in the DO are not transactional** - concurrent `run_code` calls from the same user could produce race conditions in D1. Consider wrapping multi-step workspace operations in a single sandbox execution.
- **No workspace quotas** - a single user could fill D1 with large files. Add a per-user file size limit enforced at the `run_code` tool level.

## Auth & multi-tenancy

- **One DO per MCP session, not per user** - `McpAgent.serve()` creates a fresh DO for each MCP session. The workspace is persistent (D1), but any in-memory state (e.g. caches) resets between sessions. This is correct behaviour but worth being aware of.
- **No token refresh** - OpenCode stores the OAuth token and uses it until it expires. If the Access session TTL is short (< 24h), users will need to re-authenticate. Consider increasing the Access session duration to 7 days for internal tools.
- **No rate limiting** - `run_code` creates a new Dynamic Worker on every call. Add a per-user rate limit via Cloudflare's Rate Limiting binding if you onboard many users.

## Developer experience

- **Domain tools (`codemode.*`) are hardcoded** - every user shares the same set of domain tools. A future improvement would let each user or team define their own tool set, loaded from KV or a separate Worker.
- **No streaming** - `run_code` returns the full result synchronously. For long-running code, consider returning a task ID and polling, or streaming logs via SSE.
- **`run_bundled_code` is slow** - bundles packages at runtime by fetching from the npm registry. Cache the bundled module map in KV keyed by the package manifest hash.
- **GitPrism creates a new MCP client per call** - the `@modelcontextprotocol/sdk` `Client` is stateless (GitPrism is stateless) so this is correct, but it adds connection overhead. Pool or reuse connections if GitPrism adds stateful features.

## Operations

- **No observability** - add `observability: { enabled: true }` to `wrangler.jsonc` and instrument `run_code` calls with timing and error metrics.
- **No workspace TTL** - files live forever. Add a DO Alarm on first write that cleans up workspace files older than N days.
- **Admin dashboard has no pagination** - the `GET /api/users` endpoint returns all users at once. Add cursor-based pagination once the user count grows.
