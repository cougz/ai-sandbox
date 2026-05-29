// ─── Single source of truth for built-in tool metadata ────────────────────────
//
// Both agent.ts (MCP runtime + DO admin endpoint) and access-handler.ts
// (stateless admin API) import from here.  Keeping one definition eliminates
// drift between the runtime MCP descriptions and the admin dashboard.
//
// The `domainToolNames` parameter is injected by the caller so this module
// stays free of imports from ./tools/example (avoids circular deps).
// ──────────────────────────────────────────────────────────────────────────────

export interface ToolParamDef {
  name: string;
  type: string;
  description: string;
  required: boolean;
}

export interface ToolDef {
  name: string;
  description: string;
  params: ToolParamDef[];
}

/**
 * Build the canonical tool definition array.
 *
 * @param domainToolNames – e.g. ["kvGet","kvSet","kvList","kvDelete"].
 *   Passed in so this file never imports ./tools/example directly.
 */
export function buildBuiltinToolDefs(domainToolNames: string[]): ToolDef[] {
  const codemodeList = domainToolNames.join(", ");

  return [
    // ── run_code ────────────────────────────────────────────────────────────
    {
      name: "run_code",
      description: [
        "Execute JavaScript code in an isolated V8 sandbox (~2ms startup, no network).",
        "",
        "Available in sandbox:",
        "  state.*     — your personal workspace (files persist across sessions).",
        "                Methods: readFile, writeFile, rm, glob, searchFiles,",
        "                replaceInFiles, diff, readJson, writeJson, walkTree.",
        "  shared.*    — team shared workspace (same methods as state.*).",
        "                readable and writable by all users.",
        "                Use this to access shared templates, configs, and team resources.",
        `  codemode.*  — domain tools: ${codemodeList}`,
        "               Note: kvGet/kvSet/kvList/kvDelete are deprecated stubs that",
        "               do NOT persist data. Use state.* methods for durable storage.",
        "",
        "Files written via state.* persist in your personal workspace.",
        "Files written via shared.* are immediately visible to all team members.",
        "The code must be an async arrow function or a block of statements.",
        "No npm packages or import() — use run_bundled_code for that.",
        "",
        "Returns JSON: { result: <your return value>, logs: string[], error: string | null }",
      ].join("\n"),
      params: [
        {
          name: "code",
          type: "string",
          description:
            "JavaScript to run. Can use state.*, shared.*, and codemode.*",
          required: true,
        },
      ],
    },

    // ── run_bundled_code ────────────────────────────────────────────────────
    {
      name: "run_bundled_code",
      description: [
        "Like run_code, but installs npm packages at runtime so the sandbox can import them.",
        "Prefer run_code for simple tasks — it's much faster (~2ms vs ~2-10s startup).",
        "Use dynamic import(): const { chunk } = await import('lodash');",
        "state.*, shared.*, and codemode.* are available exactly as in run_code.",
      ].join("\n"),
      params: [
        {
          name: "code",
          type: "string",
          description:
            "JavaScript to run. Use dynamic import() to load declared packages.",
          required: true,
        },
        {
          name: "packages",
          type: "object",
          description:
            'Map of npm package names to semver ranges, e.g. { "lodash": "^4.17.0", "date-fns": "*" }. Keys are package names, values are version ranges.',
          required: false,
        },
      ],
    },

    // ── get_url ───────────────────────────────────────────────────────────
    {
      name: "get_url",
      description: [
        "Get a shareable browser URL for a file in the sandbox workspace.",
        "Defaults to your personal workspace (state.*). Set shared=true for",
        "the team shared workspace (shared.*).",
        "URLs are stable and not session-bound.",
        "",
        "By default the URL is public — anyone with the link can view the file.",
        "To require a password before the file is served, use `protect_file` AFTER",
        "generating the URL — the URL itself stays the same; recipients are simply",
        "prompted for the password.",
      ].join("\n"),
      params: [
        {
          name: "file",
          type: "string",
          description:
            "Workspace path, e.g. /reports/sales-q4.html",
          required: true,
        },
        {
          name: "shared",
          type: "boolean",
          description:
            "true = shared workspace, false = personal (default)",
          required: false,
        },
      ],
    },

    // ── tool_create ────────────────────────────────────────────────────────
    {
      name: "tool_create",
      description: [
        "Create or update a reusable custom MCP tool in your personal or shared workspace.",
        "The tool is saved to /tools/{name}/tool.json and registered immediately in this session.",
        "It will be auto-loaded at the start of every future session.",
        "",
        "Set global=true to save to the Shared Workspace (visible to all users and shown in the Admin Panel).",
        "Default is false (Personal Workspace — only visible to you).",
        "",
        "Tool layout (directory format — new standard):",
        "  /tools/{name}/tool.json   ← required: tool definition (this file)",
        "  /tools/{name}/README.md   ← optional: usage docs",
        "  /tools/{name}/*.html      ← optional: HTML templates",
        "  /tools/{name}/*.md        ← optional: reference data / framework docs",
        "",
        "Schema format: { fieldName: { type, description?, optional? } }",
        "  type: 'string' | 'number' | 'boolean' | 'array' | 'object'",
        "",
        "Code: an async arrow function receiving the tool args as an object.",
        "  It has access to state.*, shared.*, and codemode.* — same as run_code.",
        "",
        "Example:",
        "  name: 'render_cf_report'",
        "  description: 'Render data into the Cloudflare HTML report template'",
        "  schema: { title: { type: 'string' }, data: { type: 'object' } }",
        "  code: 'async ({ title, data }) => {",
        '    const tpl = await shared.readFile("/tools/render_cf_report/template.html");',
        '    return tpl.replace("{{title}}", title).replace("{{data}}", JSON.stringify(data));',
        "  }'",
      ].join("\n"),
      params: [
        { name: "name", type: "string", description: "Tool name — lowercase letters, digits, and underscores only", required: true },
        { name: "description", type: "string", description: "What the tool does — shown to the AI in every session", required: true },
        { name: "schema", type: "object", description: "Parameter schema — omit or pass {} for tools with no arguments", required: false },
        { name: "code", type: "string", description: "Async arrow function, e.g. async ({ arg1, arg2 }) => { ... }", required: true },
        { name: "global", type: "boolean", description: "Save to shared workspace (visible to all users) — default false (personal workspace)", required: false },
      ],
    },

    // ── tool_list ──────────────────────────────────────────────────────────
    {
      name: "tool_list",
      description: [
        "List all available MCP tools — built-in tools and your custom tools.",
        "Scans /tools/{name}/tool.json (directory format) and /tools/{name}.json (flat format).",
      ].join("\n"),
      params: [],
    },

    // ── tool_delete ────────────────────────────────────────────────────────
    {
      name: "tool_delete",
      description: [
        "Delete a custom tool from your personal workspace.",
        "Tries /tools/{name}/tool.json (directory format) then /tools/{name}.json (flat format).",
        "The tool remains callable for the rest of this session but will not load in future sessions.",
        "Note: only tool.json is deleted; other files in the tool directory are kept.",
      ].join("\n"),
      params: [
        { name: "name", type: "string", description: "Name of the custom tool to delete", required: true },
      ],
    },

    // ── tool_reload ────────────────────────────────────────────────────────
    {
      name: "tool_reload",
      description: [
        "Reload custom tools from /tools/ in both the shared and personal workspaces.",
        "Scans /tools/{name}/tool.json (directory format) and /tools/{name}.json (flat format).",
        "Use this after writing tool files manually via run_code to register them",
        "in the current session without starting a new one.",
        "Also updates already-registered tools whose code or description has changed.",
      ].join("\n"),
      params: [],
    },

    // ── workspace_import ───────────────────────────────────────────────────
    {
      name: "workspace_import",
      description: [
        "Write data directly to a workspace file. The content is passed as a parameter",
        "and written to the specified path — only a small metadata object is returned,",
        "so the data does NOT echo back into the LLM context. This is the preferred way",
        "to move large payloads (JSON API responses, CSV data, CLI output) into the",
        "workspace without doubling context usage.",
        "",
        "CHUNKED IMPORT for large files (>100KB):",
        "  When content is too large to send in a single tool call (e.g. LLM output token",
        "  limits), set append=true to write in multiple smaller chunks. The first call",
        "  creates the file (or overwrites if append=false), subsequent calls with",
        "  append=true add to the end of the file. The response includes chunk_number and",
        "  total_bytes so you can track progress.",
        "  Example workflow for a 300KB JSON file:",
        "    1. workspace_import(content=chunk1, path='/data/big.json')           ← creates file",
        "    2. workspace_import(content=chunk2, path='/data/big.json', append=true)  ← appends",
        "    3. workspace_import(content=chunk3, path='/data/big.json', append=true)  ← appends",
        "",
        "Supports an optional Salesforce Aura response parser: set parse_salesforce_aura=true",
        "to automatically extract certification records from a Chrome DevTools network",
        "capture of a Salesforce runReport response. The parsed records array (ready for",
        "enablement_report) is written as JSON to the destination path.",
        "NOTE: parse_salesforce_aura is incompatible with append — the full response must",
        "be sent in a single call for parsing to work correctly.",
        "",
        "LARGE FILES (>100KB): use workspace_upload_url instead. It generates a single-use",
        "upload URL, then you curl the file directly from disk — no LLM output tokens used.",
        "See workspace_upload_url for the full workflow.",
        "",
        "Common patterns:",
        "  • CLI output → workspace: pipe cloudflared/curl output into workspace_import",
        "  • Chrome DevTools → workspace: capture network response, import with parsing",
        "  • Any large data → workspace: avoid run_code round-trip for simple file writes",
        "  • Chunked import → for files >100KB, split and send with append=true",
        "  • Very large files → use workspace_upload_url + bash curl instead",
      ].join("\n"),
      params: [
        { name: "content", type: "string", description: "The data to write — any string content (JSON, CSV, HTML, plain text, etc.)", required: true },
        { name: "path", type: "string", description: "Destination path in the workspace, e.g. '/data/salesforce-response.json'", required: true },
        { name: "shared", type: "boolean", description: "true = write to shared workspace, false = personal workspace (default)", required: false },
        { name: "append", type: "boolean", description: "If true, appends content to the existing file instead of overwriting. Use for chunked imports of large files that exceed LLM output token limits. The first call creates the file (append=false, the default), subsequent calls with append=true add to the end. Incompatible with parse_salesforce_aura.", required: false },
        { name: "parse_salesforce_aura", type: "boolean", description: "If true, treats content as a raw Salesforce Aura/Lightning runReport response and extracts certification records automatically. The parsed records array is written as JSON to the destination path. Use this when importing Chrome DevTools network responses from Salesforce report pages. Incompatible with append — the full response must be sent in a single call for parsing to work correctly.", required: false },
      ],
    },

    // ── workspace_export ───────────────────────────────────────────────────
    {
      name: "workspace_export",
      description: [
        "Read a file from the workspace and return its content.",
        "Useful when you need workspace file data without writing run_code.",
        "For large files, prefer using run_code with state.readFile() to process",
        "data in the sandbox rather than pulling it all into LLM context.",
      ].join("\n"),
      params: [
        { name: "path", type: "string", description: "Source path in the workspace, e.g. '/data/salesforce-response.json'", required: true },
        { name: "shared", type: "boolean", description: "true = read from shared workspace, false = personal workspace (default)", required: false },
      ],
    },

    // ── workspace_upload_url ─────────────────────────────────────────────
    {
      name: "workspace_upload_url",
      description: [
        "Generate a single-use upload URL for importing large files into the workspace.",
        "Use this when file content is too large to pass inline via workspace_import",
        "(e.g. >100KB JSON, CSV, or Salesforce responses that exceed LLM output token limits).",
        "",
        "WORKFLOW:",
        "  1. Call workspace_upload_url(path='/data/big-file.json') → returns an upload URL",
        "  2. Use bash: curl -X POST --data-binary @/path/to/local/file \"<upload_url>\"",
        "  3. The file is written directly to the workspace — no LLM output tokens used.",
        "",
        "The upload URL is single-use and expires in 5 minutes.",
        "The curl command streams the file directly from disk to the server.",
        "This bypasses all LLM token limits — files of any size can be uploaded.",
      ].join("\n"),
      params: [
        { name: "path", type: "string", description: "Destination path in the workspace, e.g. '/data/salesforce-response.json'", required: true },
        { name: "shared", type: "boolean", description: "true = write to shared workspace, false = personal workspace (default)", required: false },
        { name: "parse_salesforce_aura", type: "boolean", description: "If true, the uploaded content will be parsed as a Salesforce Aura response and records extracted automatically.", required: false },
      ],
    },

    // ── protect_file ───────────────────────────────────────────────────────
    {
      name: "protect_file",
      description: [
        "Set or rotate a password on a workspace file so the /view URL prompts for the password before serving it.",
        "",
        "USE THIS TOOL when the user asks to:",
        "  • \"protect\", \"lock\", or \"password-protect\" a file",
        "  • \"make a file secret\" or \"make a file private\"",
        "  • \"add a password\" or \"set a password\" on a report",
        "  • \"rotate\" or \"change\" an existing password",
        "",
        "Behaviour:",
        "  • Public /view URLs continue to work for unprotected files (unchanged behaviour).",
        "  • Protected files render an unlock prompt; recipients enter the password once,",
        "    then receive a 24h cookie scoped to /view.",
        "  • Five failed attempts within 10 minutes trigger a 5-minute lockout.",
        "",
        "Password handling:",
        "  • If the user supplies a password, use it as-is.",
        "  • If the user does NOT supply a password, omit the parameter — the server generates",
        "    a 4-word diceware password (e.g. \"calm-river-bear-five\") and returns it.",
        "  • ALWAYS surface the password back to the user in your reply so they can share it",
        "    with recipients through a separate channel.",
        "",
        "Authorization (shared workspace only):",
        "  • You can only rotate or change a password on a file YOU originally protected.",
        "  • If the file was protected by someone else, the tool returns a forbidden error.",
        "",
        "The /view URL itself does NOT change when protection is added — anyone using the existing",
        "link will simply be prompted for the password from now on.",
      ].join("\n"),
      params: [
        { name: "file", type: "string", description: "Workspace path, e.g. '/reports/board-deck.html'", required: true },
        { name: "password", type: "string", description: "Password to set. Omit to have the server generate a diceware password (recommended unless the user supplies one).", required: false },
        { name: "shared", type: "boolean", description: "true = file lives in the shared workspace, false = personal workspace (default)", required: false },
      ],
    },

    // ── unprotect_file ─────────────────────────────────────────────────────
    {
      name: "unprotect_file",
      description: [
        "Remove the password from a previously-protected file. After this, the /view URL is",
        "publicly accessible again (same behaviour as before protection was added).",
        "",
        "USE THIS TOOL when the user asks to \"remove the password\", \"unprotect\", \"unlock\",",
        "or \"make a file public again\".",
        "",
        "Authorization (shared workspace): you can only remove a password from a file you",
        "originally protected, unless you are an admin.",
      ].join("\n"),
      params: [
        { name: "file", type: "string", description: "Workspace path of a previously-protected file", required: true },
        { name: "shared", type: "boolean", description: "true = shared workspace, false = personal workspace (default)", required: false },
      ],
    },

    // ── list_protected_files ───────────────────────────────────────────────
    {
      name: "list_protected_files",
      description: [
        "List all files in the user's workspace(s) that currently have a password set.",
        "",
        "Returns metadata only (file path, creator email, creation/rotation timestamps).",
        "Never returns the password or its hash.",
        "",
        "Use this to answer questions like \"which of my files are protected?\" or",
        "\"show me my locked reports\".",
      ].join("\n"),
      params: [
        { name: "shared", type: "boolean", description: "true = list shared-workspace protections, false = personal workspace (default). Both lists are always returned regardless.", required: false },
      ],
    },
  ];
}
