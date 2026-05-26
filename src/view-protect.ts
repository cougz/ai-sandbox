// ─── /view password-protection store ───────────────────────────────────────────
//
// Per-file opt-in password protection for the public /view endpoint.
//
// Storage:  OAUTH_KV under key `protect:<workspace>:<urlencoded-file>`
// Hashing:  PBKDF2-SHA256, 100k iterations, per-record 16-byte salt, 32-byte key
// Cookie:   `__Host-VIEW_<sha1(workspace|file)>` — HMAC of (workspace|file|exp)
//           signed with COOKIE_ENCRYPTION_KEY, 24h TTL
//
// Authorization (mutations):
//   - Personal workspace: workspace owner OR admin
//   - Shared workspace:   record creator OR admin (creator-locks, decision #2)
//
// Rate limit (verify): 5 failures within 10 minutes → 5-minute lockout per record.

import { emailToNamespace, SHARED_NAMESPACE } from "./namespace";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ProtectionRecord {
  salt:        string;          // hex
  hash:        string;          // hex (PBKDF2-SHA256, 100k, 32 bytes)
  createdAt:   string;          // ISO timestamp
  createdBy:   string;          // workspace owner email at the time of protection
  rotatedAt:   string | null;
  failCount:   number;
  lockedUntil: string | null;   // ISO; cleared on successful verify
}

export interface ProtectionMetadata {
  createdAt: string;
  createdBy: string;
  rotatedAt: string | null;
}

const PBKDF2_ITERATIONS  = 100_000;
const KEY_LENGTH_BYTES   = 32;
const SALT_LENGTH_BYTES  = 16;
const MAX_FAIL_BEFORE_LOCK = 5;
const LOCKOUT_MS         = 5 * 60 * 1000;   // 5 minutes
const COOKIE_TTL_SECONDS = 24 * 60 * 60;    // 24 hours (decision #8)

// ─── Helpers ──────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const dec = new TextDecoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(s: string): Uint8Array {
  const m = s.match(/.{1,2}/g);
  if (!m) return new Uint8Array(0);
  return new Uint8Array(m.map(b => parseInt(b, 16)));
}

function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

/** Constant-time hex string comparison */
function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Resolve dashboard workspace identifier (email or "shared") to namespace string */
export function resolveNamespace(workspace: string): string {
  if (workspace === "shared" || workspace === SHARED_NAMESPACE) return SHARED_NAMESPACE;
  return emailToNamespace(workspace);
}

/** KV key for a (workspace, file) pair */
function protectKey(ns: string, file: string): string {
  return `protect:${ns}:${encodeURIComponent(file)}`;
}

// ─── PBKDF2 ───────────────────────────────────────────────────────────────────

async function pbkdf2(password: string, salt: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    key,
    KEY_LENGTH_BYTES * 8,
  );
  return toHex(bits);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** Look up the protection record for a (workspace, file). Returns null if unprotected. */
export async function getProtection(
  kv: KVNamespace,
  workspace: string,
  file: string,
): Promise<ProtectionRecord | null> {
  const raw = await kv.get(protectKey(resolveNamespace(workspace), file));
  if (!raw) return null;
  try { return JSON.parse(raw) as ProtectionRecord; } catch { return null; }
}

/**
 * Set or rotate the password protection on a file.
 * Pass action="set" to create a fresh record (or overwrite if forceOverwrite=true).
 * Pass action="rotate" to update an existing record's hash + rotatedAt.
 *
 * Throws Error with `code: "forbidden"` if the actor is not the creator or an admin
 * and the file is in the shared workspace.
 */
export async function setProtection(
  kv: KVNamespace,
  opts: {
    workspace:    string;
    file:         string;
    password:     string;
    actorEmail:   string;
    actorIsAdmin: boolean;
    rotate?:      boolean;
  },
): Promise<ProtectionRecord> {
  const ns = resolveNamespace(opts.workspace);
  const key = protectKey(ns, opts.file);

  const existing = await getProtection(kv, opts.workspace, opts.file);

  // Authorization — shared workspace requires creator/admin to modify existing record.
  if (existing && ns === SHARED_NAMESPACE) {
    if (existing.createdBy !== opts.actorEmail && !opts.actorIsAdmin) {
      const err = new Error("Only the file's protection creator or an admin can change it.");
      (err as Error & { code?: string }).code = "forbidden";
      throw err;
    }
  }

  const salt = randomBytes(SALT_LENGTH_BYTES);
  const hash = await pbkdf2(opts.password, salt);
  const now  = new Date().toISOString();

  const record: ProtectionRecord = {
    salt: toHex(salt),
    hash,
    createdAt:   existing?.createdAt ?? now,
    createdBy:   existing?.createdBy ?? opts.actorEmail,
    rotatedAt:   existing || opts.rotate ? now : null,
    failCount:   0,
    lockedUntil: null,
  };

  await kv.put(key, JSON.stringify(record));
  return record;
}

/** Remove protection from a file. Authorization same as setProtection. */
export async function clearProtection(
  kv: KVNamespace,
  opts: { workspace: string; file: string; actorEmail: string; actorIsAdmin: boolean },
): Promise<{ removed: boolean }> {
  const ns = resolveNamespace(opts.workspace);
  const existing = await getProtection(kv, opts.workspace, opts.file);
  if (!existing) return { removed: false };

  if (ns === SHARED_NAMESPACE && existing.createdBy !== opts.actorEmail && !opts.actorIsAdmin) {
    const err = new Error("Only the file's protection creator or an admin can remove it.");
    (err as Error & { code?: string }).code = "forbidden";
    throw err;
  }

  await kv.delete(protectKey(ns, opts.file));
  return { removed: true };
}

/** Self-healing helper used by /view when the underlying file no longer exists. */
export async function deleteProtectionUnchecked(
  kv: KVNamespace,
  workspace: string,
  file: string,
): Promise<void> {
  await kv.delete(protectKey(resolveNamespace(workspace), file));
}

/**
 * Verify a password attempt against a protection record.
 * Updates failCount/lockedUntil/persists in KV as a side-effect.
 *
 * Returns:
 *   "ok"          → password matched, cookie can be set
 *   "wrong"       → password incorrect (counter incremented)
 *   "locked"      → record currently in lockout window
 *   "not_found"   → no protection record (caller should treat as "wrong" for opacity)
 */
export async function verifyProtection(
  kv: KVNamespace,
  workspace: string,
  file: string,
  password: string,
): Promise<"ok" | "wrong" | "locked" | "not_found"> {
  const ns  = resolveNamespace(workspace);
  const key = protectKey(ns, file);
  const record = await getProtection(kv, workspace, file);
  if (!record) return "not_found";

  if (record.lockedUntil && new Date(record.lockedUntil).getTime() > Date.now()) {
    return "locked";
  }

  const submittedHash = await pbkdf2(password, fromHex(record.salt));
  const ok = constantTimeEqualHex(submittedHash, record.hash);

  if (ok) {
    record.failCount   = 0;
    record.lockedUntil = null;
    await kv.put(key, JSON.stringify(record));
    return "ok";
  } else {
    record.failCount = (record.failCount ?? 0) + 1;
    if (record.failCount >= MAX_FAIL_BEFORE_LOCK) {
      record.lockedUntil = new Date(Date.now() + LOCKOUT_MS).toISOString();
      record.failCount   = 0; // reset counter after locking
    }
    await kv.put(key, JSON.stringify(record));
    return "wrong";
  }
}

/** Compute the cookie name that holds the unlock token for a (workspace, file). */
export async function unlockCookieName(workspace: string, file: string): Promise<string> {
  const ns = resolveNamespace(workspace);
  const data = enc.encode(`${ns}|${file}`);
  const hash = await crypto.subtle.digest("SHA-1", data);
  return `__Host-VIEW_${toHex(hash).slice(0, 16)}`;
}

/** Build the Set-Cookie value for a successful unlock. */
export async function buildUnlockCookie(
  workspace: string,
  file: string,
  secret: string,
): Promise<{ name: string; value: string; setCookie: string }> {
  const name = await unlockCookieName(workspace, file);
  const ns   = resolveNamespace(workspace);
  const exp  = Math.floor(Date.now() / 1000) + COOKIE_TTL_SECONDS;
  const payload = `${ns}|${file}|${exp}`;
  const payloadB64 = btoa(payload);
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const raw = await crypto.subtle.sign("HMAC", key, enc.encode(payloadB64));
  const sig = toHex(raw);
  const value = `${sig}.${payloadB64}`;
  // __Host- prefix requires Path=/ (browser will silently reject the cookie otherwise).
  const setCookie = `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${COOKIE_TTL_SECONDS}`;
  return { name, value, setCookie };
}

/** Validate a previously-issued unlock cookie. Returns true iff the HMAC matches AND payload not expired AND payload matches (workspace, file). */
export async function checkUnlockCookie(
  request: Request,
  workspace: string,
  file: string,
  secret: string,
): Promise<boolean> {
  const cookieName = await unlockCookieName(workspace, file);
  const header = request.headers.get("Cookie") ?? "";
  const match = header.split(";").map(c => c.trim()).find(c => c.startsWith(`${cookieName}=`));
  if (!match) return false;
  const raw = match.slice(cookieName.length + 1);
  const dot = raw.indexOf(".");
  if (dot < 1) return false;
  const sig = raw.slice(0, dot);
  const payloadB64 = raw.slice(dot + 1);

  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
  );
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      "HMAC", key,
      fromHex(sig) as BufferSource,
      enc.encode(payloadB64),
    );
  } catch { return false; }
  if (!valid) return false;

  let payload: string;
  try { payload = atob(payloadB64); } catch { return false; }
  const parts = payload.split("|");
  if (parts.length !== 3) return false;
  const [pns, pfile, pexp] = parts;
  if (pns !== resolveNamespace(workspace)) return false;
  if (pfile !== file) return false;
  const exp = parseInt(pexp, 10);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return false;
  return true;
}

// ─── CSRF token for /view/unlock POST ─────────────────────────────────────────
//
// Signs (workspace|file|epoch-minute) with COOKIE_ENCRYPTION_KEY.  Validity window
// is ~15 minutes (current minute ± 14) so a token created on page render survives
// the user thinking, but doesn't enable replay attacks long after the fact.

export async function createCsrfToken(
  workspace: string,
  file: string,
  secret: string,
): Promise<string> {
  const ns  = resolveNamespace(workspace);
  const ts  = Math.floor(Date.now() / 60_000);
  const payload = `${ns}|${file}|${ts}`;
  const payloadB64 = btoa(payload);
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const raw = await crypto.subtle.sign("HMAC", key, enc.encode(payloadB64));
  return `${toHex(raw)}.${payloadB64}`;
}

export async function verifyCsrfToken(
  token: string,
  workspace: string,
  file: string,
  secret: string,
): Promise<boolean> {
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const sig = token.slice(0, dot);
  const payloadB64 = token.slice(dot + 1);
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
  );
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      "HMAC", key,
      fromHex(sig) as BufferSource,
      enc.encode(payloadB64),
    );
  } catch { return false; }
  if (!valid) return false;
  let payload: string;
  try { payload = atob(payloadB64); } catch { return false; }
  const parts = payload.split("|");
  if (parts.length !== 3) return false;
  const [pns, pfile, pts] = parts;
  if (pns !== resolveNamespace(workspace)) return false;
  if (pfile !== file) return false;
  const ts = parseInt(pts, 10);
  if (!Number.isFinite(ts)) return false;
  const now = Math.floor(Date.now() / 60_000);
  return Math.abs(now - ts) <= 14;
}

// ─── List protections for a workspace ─────────────────────────────────────────
//
// Used by /api/files (dashboard) and the `list_protected_files` MCP tool.
// Returns a map of file path → metadata (no hash/salt).
//
// KV.list scans by prefix; for each match we decode the file from the suffix.

export async function listProtections(
  kv: KVNamespace,
  workspace: string,
): Promise<Record<string, ProtectionMetadata>> {
  const ns = resolveNamespace(workspace);
  const prefix = `protect:${ns}:`;
  const out: Record<string, ProtectionMetadata> = {};
  let cursor: string | undefined;
  do {
    const page: KVNamespaceListResult<unknown, string> = await kv.list({ prefix, cursor });
    for (const k of page.keys) {
      const filePart = k.name.slice(prefix.length);
      let decoded: string;
      try { decoded = decodeURIComponent(filePart); } catch { continue; }
      const raw = await kv.get(k.name);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw) as ProtectionRecord;
        out[decoded] = {
          createdAt: rec.createdAt,
          createdBy: rec.createdBy,
          rotatedAt: rec.rotatedAt,
        };
      } catch { /* skip malformed */ }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

// ─── Diceware password generator ──────────────────────────────────────────────
//
// 256-word EFF-style mini wordlist (short, common, dictation-friendly).
// 4 words ≈ 32 bits of entropy — acceptable for casual sharing.  Users can
// supply their own password or paste a longer one for stronger threat models.

const DICEWARE_WORDS = [
  "able","acid","aged","also","area","army","atom","baby","back","bake","ball","band",
  "bank","bare","barn","base","bath","beam","bean","bear","beat","bell","belt","bend",
  "best","bike","bind","bird","bite","blue","boat","body","bold","bolt","bone","book",
  "boom","boot","bore","born","both","bowl","brag","brew","brim","buck","bulk","bull",
  "burn","bush","busy","cake","calf","calm","came","camp","cane","cape","card","care",
  "carp","cart","case","cash","cast","cave","cell","chat","chef","chin","chip","chop",
  "city","clam","clap","claw","clay","clip","club","clue","coal","coat","code","coil",
  "coin","cold","colt","come","cook","cool","cope","copy","cord","core","cork","corn",
  "cost","cove","crab","cram","crew","crib","crop","crow","cube","cult","cure","curl",
  "cute","damp","dart","dash","date","dawn","dazy","deal","dean","dear","debt","deck",
  "deep","deer","dent","desk","dial","dice","dish","disk","dive","dock","does","dole",
  "doll","dome","done","door","dose","dove","down","drag","draw","drew","drip","drop",
  "drum","duck","duct","dune","dusk","dust","duty","each","earn","ease","east","easy",
  "echo","edge","emit","envy","epic","even","exam","exit","face","fact","fade","fair",
  "fall","fame","fang","fare","farm","fast","fate","fawn","fear","feat","feed","feel",
  "felt","fern","fest","feud","fiat","fiel","figs","file","fill","film","find","fine",
  "fire","firm","fish","fist","five","flag","flap","flat","flee","flew","flip","flop",
  "flow","foam","foil","fold","folk","fond","font","food","foot","fork","form","fort",
  "foul","four","fowl","frog","from","fuel","full","fume","fund","fuse","fuzz","gain",
  "game","gate","gear","germ","gift","girl","give","glad","glue","goal","goat","gold",
  "gone","good","grab","grew","grin","grip","grow","gulf","hail","hair","half","hall",
  "halt","hand","harm","hawk","hay","heal","heap"
];

export function generateDicewarePassword(words = 4): string {
  const out: string[] = [];
  for (let i = 0; i < words; i++) {
    const idx = Math.floor((randomBytes(2)[0] * 256 + randomBytes(2)[0]) % DICEWARE_WORDS.length);
    out.push(DICEWARE_WORDS[idx]);
  }
  return out.join("-");
}
