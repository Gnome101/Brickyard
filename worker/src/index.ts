/**
 * Cloudflare Worker powering the Brickyard backend API.
 * Handles routing, validation, caching, rate limiting, and Snowflake integration.
 */

declare global {
  interface ExecutionContext {
    waitUntil(promise: Promise<unknown>): void;
    passThroughOnException(): void;
  }

  interface KVNamespace {
    get(key: string): Promise<string | null>;
    put(key: string, value: string, options?: { expiration?: number; expirationTtl?: number }): Promise<void>;
  }

  interface D1PreparedStatement {
    bind(...values: unknown[]): D1PreparedStatement;
    first<T = unknown>(): Promise<T | null>;
    all<T = unknown>(): Promise<{ results: T[] }>;
    run<T = unknown>(): Promise<T>;
  }

  interface D1Database {
    prepare(query: string): D1PreparedStatement;
  }
}

export interface LDrawPart {
  ldraw_part: string; // e.g. "3001.dat"
  color: number; // LDraw color ID
  pos: [number, number, number]; // [x, y, z] in LDU
  rot: [0 | 90 | 180 | 270, 0 | 90 | 180 | 270, 0 | 90 | 180 | 270];
}

export interface Env {
  DESIGN_CACHE: KVNamespace;
  DB: D1Database;
  MODEL_MAX_ITEMS: string;
  MODEL_MAX_BYTES: string;
  POS_MIN: string;
  POS_MAX: string;
  SNOWFLAKE_TIMEOUT_MS: string;
  RATE_LIMIT_REQUESTS: string;
  RATE_LIMIT_WINDOW_S: string;
  SNOWFLAKE_ENDPOINT: string;
  SNOWFLAKE_API_KEY?: string;
  // Optional: customize which header carries the API key (default: "X-API-Key")
  SNOWFLAKE_API_KEY_HEADER?: string;
  // Worker access control: require a client API key via header
  CLIENT_API_KEY?: string;
  CLIENT_API_KEY_HEADER?: string; // default: X-Client-Key
  // Optional default upstream model name for the new Snowflake API
  // (e.g., "claude-3-5-sonnet"). If not provided, a sensible default is used.
  SNOWFLAKE_MODEL?: string;
}

interface DesignRequest {
  prompt: string;
  agent_types: string[];
  seed?: number; // Optional seed forwarded to Snowflake teammate.
}

interface VoteRequest {
  agent_type: string;
  prompt: string;
}

type Leaderboard = Record<string, number>;
// Legacy types retained for reference; no longer used in the refactored design handler.
// type AgentDesigns = Record<string, LDrawPart[]>;
// type CacheHits = Record<string, boolean>;

interface HandlerContext {
  request: Request;
  env: Env;
  ctx: ExecutionContext;
  requestId: string;
  corsOrigin: string;
}

class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details: unknown;

  constructor(code: string, message: string, status = 400, details: unknown = {}) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

const MAX_BODY_BYTES = 256 * 1024; // Keep POST payloads under 256 KB.

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = makeRequestId();
    const corsOrigin = "*";

    if (request.method === "OPTIONS") {
      return handleOptions(corsOrigin, env);
    }

    try {
      await limitBodySize(request, MAX_BODY_BYTES);
      const url = new URL(request.url);
      const handlerContext: HandlerContext = { request, env, ctx, requestId, corsOrigin };

      if (url.pathname === "/api/design" && request.method === "POST") {
        ensureClientAuth(request, env);
        return await handleDesign(handlerContext);
      }

      if (url.pathname === "/api/vote" && request.method === "POST") {
        ensureClientAuth(request, env);
        return await handleVote(handlerContext);
      }

      if (url.pathname === "/api/leaderboard" && request.method === "GET") {
        ensureClientAuth(request, env);
        return await handleLeaderboard(handlerContext);
      }

      if (url.pathname === "/healthz" && request.method === "GET") {
        return handleHealthz(corsOrigin, requestId);
      }

      throw new ApiError("NOT_FOUND", "Unknown route", 404);
    } catch (error) {
      if (error instanceof ApiError) {
        return errorResponse(error, requestId, corsOrigin);
      }

      console.error(`[${requestId}] Unhandled error`, error);
      return errorResponse(new ApiError("INTERNAL_ERROR", "Unexpected failure", 500), requestId, corsOrigin);
    }
  },
};

async function handleDesign({ request, env, ctx, requestId, corsOrigin }: HandlerContext): Promise<Response> {
  // Accept the new simplified contract: single model request, return raw LDraw (.ldr) text.
  // For compatibility, accept either `model`, `agent_type`, or the first of `agent_types`.
  const raw = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const prompt = typeof raw.prompt === "string" ? raw.prompt.trim() : "";
  const modelFromArray = Array.isArray(raw.agent_types) && raw.agent_types.length > 0
    ? String(raw.agent_types[0])
    : "";
  const modelName = [
    typeof raw.model === "string" ? raw.model.trim() : "",
    typeof raw.agent_type === "string" ? raw.agent_type.trim() : "",
    modelFromArray.trim(),
    env.SNOWFLAKE_MODEL && env.SNOWFLAKE_MODEL.trim().length > 0 ? env.SNOWFLAKE_MODEL.trim() : "",
  ].find((v) => v.length > 0) || "claude-3-5-sonnet";

  const seed = typeof raw.seed === "number" && Number.isFinite(raw.seed)
    ? Math.floor(raw.seed)
    : Math.floor(Math.random() * 1_000_000);

  if (!prompt) {
    throw new ApiError("VALIDATION_FAILED", "prompt is required", 400, { field: "prompt" });
  }

  await enforceRateLimit(env, request, requestId);

  const ldr = await fetchLdr(env, prompt, modelName, seed, requestId);
  return okText(ldr, requestId, corsOrigin);
}

async function handleVote({ request, env, requestId, corsOrigin }: HandlerContext): Promise<Response> {
  const payload = (await request.json().catch(() => ({}))) as Partial<VoteRequest>;

  const prompt = typeof payload.prompt === "string" ? payload.prompt.trim() : "";
  const agentType = typeof payload.agent_type === "string" ? payload.agent_type.trim() : "";

  if (!prompt || !agentType) {
    throw new ApiError("VALIDATION_FAILED", "agent_type and prompt are required", 400, { field: "agent_type" });
  }

  await env.DB.prepare(
    "INSERT INTO votes (agent_type, prompt, count) VALUES (?1, ?2, 1) " +
      "ON CONFLICT(agent_type, prompt) DO UPDATE SET count = count + 1"
  )
    .bind(agentType, prompt)
    .run();

  const leaderboard = await loadLeaderboard(env);

  return ok({ leaderboard }, requestId, corsOrigin);
}

async function handleLeaderboard({ env, requestId, corsOrigin }: HandlerContext): Promise<Response> {
  const leaderboard = await loadLeaderboard(env);

  return ok({ leaderboard, updated_at: new Date().toISOString() }, requestId, corsOrigin);
}

function handleHealthz(corsOrigin: string, requestId: string): Response {
  return ok({ ok: true }, requestId, corsOrigin);
}

function handleOptions(corsOrigin: string, env: Env): Response {
  const clientHeader = (env.CLIENT_API_KEY_HEADER?.trim() || "X-Client-Key").toLowerCase();
  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(corsOrigin, {
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": `content-type,x-requested-with,${clientHeader}`,
      "access-control-max-age": "86400",
    }),
  });
}

function ok<T extends Record<string, unknown>>(data: T, requestId: string, origin: string, status = 200): Response {
  const body = JSON.stringify({ ...data, request_id: requestId });
  return new Response(body, {
    status,
    headers: buildCorsHeaders(origin, { "content-type": "application/json" }),
  });
}

function okText(body: string, requestId: string, origin: string, status = 200): Response {
  // Return raw LDraw text; include request ID as a response header for tracing.
  const headers = buildCorsHeaders(origin, { "content-type": "text/plain; charset=utf-8", "x-request-id": requestId });
  return new Response(body, { status, headers });
}

function errorResponse(error: ApiError, requestId: string, origin: string): Response {
  const body = JSON.stringify({
    error: { code: error.code, message: error.message, details: error.details ?? {} },
    request_id: requestId,
  });

  return new Response(body, {
    status: error.status,
    headers: buildCorsHeaders(origin, { "content-type": "application/json" }),
  });
}

function buildCorsHeaders(origin: string, additional: Record<string, string> = {}): Headers {
  // Open CORS for simplicity; access is controlled via CLIENT_API_KEY.
  const headers = new Headers({ "access-control-allow-origin": origin, ...additional });
  return headers;
}

function ensureClientAuth(request: Request, env: Env): void {
  const required = env.CLIENT_API_KEY?.trim();
  if (!required) {
    // No client key configured; allow all (useful for local/dev).
    return;
  }
  const headerName = env.CLIENT_API_KEY_HEADER?.trim() || "X-Client-Key";
  const provided = request.headers.get(headerName) || request.headers.get(headerName.toLowerCase());
  if (!provided || provided.trim() !== required) {
    throw new ApiError("UNAUTHORIZED", "Missing or invalid API key", 401);
  }
}

async function loadLeaderboard(env: Env): Promise<Leaderboard> {
  const { results } = await env.DB.prepare("SELECT agent_type, SUM(count) AS total FROM votes GROUP BY agent_type")
    .all<{ agent_type: string; total: number }>();

  const leaderboard: Leaderboard = {};
  for (const row of results ?? []) {
    if (!row || typeof row.agent_type !== "string") {
      continue;
    }
    const normalizedAgent = row.agent_type;
    const total = typeof row.total === "number" ? row.total : Number(row.total ?? 0);
    leaderboard[normalizedAgent] = Number.isFinite(total) ? total : 0;
  }

  return leaderboard;
}

async function enforceRateLimit(env: Env, request: Request, requestId: string): Promise<void> {
  const ip = request.headers.get("cf-connecting-ip") ?? "anonymous";
  const windowSeconds = Number(env.RATE_LIMIT_WINDOW_S || "60");
  const maxRequests = Number(env.RATE_LIMIT_REQUESTS || "10");

  const result = await rateLimit(env, ip, windowSeconds, maxRequests);
  if (!result.allowed) {
    throw new ApiError("RATE_LIMITED", "Too many requests", 429, { retryAfter: result.retryAfter });
  }
}

async function rateLimit(env: Env, identity: string, windowSeconds: number, maxRequests: number): Promise<{ allowed: boolean; retryAfter?: number }> {
  const windowDuration = Number.isFinite(windowSeconds) && windowSeconds > 0 ? Math.floor(windowSeconds) : 60;
  const max = Number.isFinite(maxRequests) && maxRequests > 0 ? Math.floor(maxRequests) : 10;

  if (max <= 0) {
    return { allowed: true };
  }

  const now = Date.now();
  const windowId = Math.floor(now / (windowDuration * 1000));
  const key = `rl:${identity}:${windowId}`;

  const currentRaw = await env.DESIGN_CACHE.get(key);
  const currentCount = currentRaw ? Number(currentRaw) : 0;

  if (Number.isFinite(currentCount) && currentCount >= max) {
    const windowEnd = (windowId + 1) * windowDuration * 1000;
    const retryAfter = Math.max(1, Math.ceil((windowEnd - now) / 1000));
    return { allowed: false, retryAfter };
  }

  const nextCount = Number.isFinite(currentCount) && currentCount >= 0 ? currentCount + 1 : 1;
  const ttl = Math.max(windowDuration, 1);
  await env.DESIGN_CACHE.put(key, String(nextCount), { expirationTtl: ttl });

  return { allowed: true };
}

async function fetchLdr(env: Env, prompt: string, modelName: string, seed: number, requestId: string): Promise<string> {
  if (!env.SNOWFLAKE_ENDPOINT || env.SNOWFLAKE_ENDPOINT.trim().length === 0) {
    console.warn(`[${requestId}] SNOWFLAKE_ENDPOINT not configured; falling back to mock model.`);
    const parts = generateMockModel(prompt, modelName, seed);
    return partsToLdr(parts);
  }

  if (env.SNOWFLAKE_ENDPOINT.startsWith("mock:")) {
    const parts = generateMockModel(prompt, modelName, seed, env.SNOWFLAKE_ENDPOINT);
    return partsToLdr(parts);
  }

  const timeoutMsRaw = Number(env.SNOWFLAKE_TIMEOUT_MS || "5000");
  const timeoutMs = Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? timeoutMsRaw : 5000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (env.SNOWFLAKE_API_KEY) {
      const headerName = env.SNOWFLAKE_API_KEY_HEADER?.trim() || "X-API-Key";
      headers[headerName] = env.SNOWFLAKE_API_KEY;
    }

    const upstreamBody: Record<string, unknown> = {
      prompt,
      model: modelName,
      // Legacy fields (ignored by the new API, used by local mock and older upstreams):
      agent_type: modelName,
      seed,
    };

    const response = await fetch(env.SNOWFLAKE_ENDPOINT, {
      method: "POST",
      headers,
      body: JSON.stringify(upstreamBody),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new ApiError("GENERATION_FAILED", `upstream ${response.status}`, 502);
    }

    try {
      const payload = await response.json();

      // New upstream shape: { success: true, ldrContent: string, ... }
      const success = (payload as { success?: unknown }).success;
      const ldrContent = (payload as { ldrContent?: unknown }).ldrContent;
      if (success === true && typeof ldrContent === "string" && ldrContent.trim().length > 0) {
        return ldrContent as string;
      }

      // Compatibility path: local mock or legacy upstream returns { model: LDrawPart[] }
      if (payload && typeof payload === "object" && Array.isArray((payload as { model?: unknown }).model)) {
        const parts = (payload as { model: LDrawPart[] }).model;
        return partsToLdr(parts);
      }

      throw new ApiError("GENERATION_FAILED", "Invalid upstream payload", 502);
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      throw new ApiError("GENERATION_FAILED", "Unable to parse upstream response", 502);
    }
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiError("GENERATION_TIMEOUT", "Generation request timed out", 502);
    }

    throw new ApiError("GENERATION_FAILED", "Generation request failed", 502);
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Convert an array of LDrawPart entries to LDraw .ldr text.
 * Emits type-1 lines with a rotation matrix derived from Euler angles.
 */
function partsToLdr(parts: LDrawPart[]): string {
  const lines: string[] = [];
  lines.push("0 Brickyard Model");
  for (const p of parts) {
    const [rx, ry, rz] = p.rot;
    const M = eulerToMatrix(rx, ry, rz);
    const [x, y, z] = p.pos;
    // 1 color x y z a b c d e f g h i part.dat
    lines.push(
      [
        "1",
        String(Math.floor(p.color)),
        String(x),
        String(y),
        String(z),
        String(M[0][0]),
        String(M[0][1]),
        String(M[0][2]),
        String(M[1][0]),
        String(M[1][1]),
        String(M[1][2]),
        String(M[2][0]),
        String(M[2][1]),
        String(M[2][2]),
        p.ldraw_part,
      ].join(" ")
    );
  }
  return lines.join("\n");
}

/**
 * Parse a minimal subset of LDraw .ldr content into our LDrawPart[] format.
 * We only process type-1 lines (subfile references):
 *   1 color x y z a b c d e f g h i part.dat
 * Rotation matrix is converted to Euler angles in 90° steps by search.
 */
function parseLdrToParts(ldr: string, env: Env): LDrawPart[] {
  const lines = ldr.split(/\r?\n/);
  const parts: LDrawPart[] = [];
  const maxItemsRaw = Number(env.MODEL_MAX_ITEMS || "200");
  const maxItems = Number.isFinite(maxItemsRaw) && maxItemsRaw > 0 ? Math.floor(maxItemsRaw) : 200;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("0 ") || trimmed === "0") {
      continue; // comments/meta
    }
    if (!trimmed.startsWith("1 ")) {
      continue; // ignore other line types
    }

    // Tokenize. Some .ldr files use multiple spaces; split on whitespace.
    const tokens = trimmed.split(/\s+/);
    // Expect: 1 color x y z a b c d e f g h i file
    if (tokens.length < 15) {
      continue; // malformed; skip rather than fail the whole request
    }

    const color = Number(tokens[1]);
    const x = Number(tokens[2]);
    const y = Number(tokens[3]);
    const z = Number(tokens[4]);

    const a = Number(tokens[5]);
    const b = Number(tokens[6]);
    const c = Number(tokens[7]);
    const d = Number(tokens[8]);
    const e = Number(tokens[9]);
    const f = Number(tokens[10]);
    const g = Number(tokens[11]);
    const h = Number(tokens[12]);
    const i = Number(tokens[13]);

    const file = tokens[14];

    if (!Number.isFinite(color) || typeof file !== "string" || !/\.dat$/i.test(file)) {
      continue;
    }

    // Round near-integers to -1/0/1 to stabilize comparison.
    const M: number[][] = [
      [roundToUnit(a), roundToUnit(b), roundToUnit(c)],
      [roundToUnit(d), roundToUnit(e), roundToUnit(f)],
      [roundToUnit(g), roundToUnit(h), roundToUnit(i)],
    ];

    const rot = findEulerFromMatrix(M) ?? [0, 0, 0];

    parts.push({
      ldraw_part: file,
      color: Math.max(0, Math.min(1023, Math.floor(color))),
      pos: [x, y, z],
      rot,
    });

    if (parts.length >= maxItems) {
      break;
    }
  }

  return parts;
}

function roundToUnit(n: number): -1 | 0 | 1 {
  if (!Number.isFinite(n)) return 0;
  const r = Math.round(n);
  return (r < 0 ? -1 : r > 0 ? 1 : 0) as -1 | 0 | 1;
}

// Build a rotation matrix for rx, ry, rz in degrees (multiples of 90), order Z * Y * X.
function eulerToMatrix(rx: 0 | 90 | 180 | 270, ry: 0 | 90 | 180 | 270, rz: 0 | 90 | 180 | 270): number[][] {
  const Rx = (deg: number): number[][] => {
    const c = Math.round(Math.cos((deg * Math.PI) / 180));
    const s = Math.round(Math.sin((deg * Math.PI) / 180));
    return [
      [1, 0, 0],
      [0, c, -s],
      [0, s, c],
    ];
  };
  const Ry = (deg: number): number[][] => {
    const c = Math.round(Math.cos((deg * Math.PI) / 180));
    const s = Math.round(Math.sin((deg * Math.PI) / 180));
    return [
      [c, 0, s],
      [0, 1, 0],
      [-s, 0, c],
    ];
  };
  const Rz = (deg: number): number[][] => {
    const c = Math.round(Math.cos((deg * Math.PI) / 180));
    const s = Math.round(Math.sin((deg * Math.PI) / 180));
    return [
      [c, -s, 0],
      [s, c, 0],
      [0, 0, 1],
    ];
  };

  return matMul(matMul(Rz(rz), Ry(ry)), Rx(rx));
}

function matMul(A: number[][], B: number[][]): number[][] {
  const out: number[][] = [
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
  ];
  for (let r = 0; r < 3; r += 1) {
    for (let c = 0; c < 3; c += 1) {
      out[r][c] = A[r][0] * B[0][c] + A[r][1] * B[1][c] + A[r][2] * B[2][c];
      out[r][c] = roundToUnit(out[r][c]);
    }
  }
  return out;
}

function matricesEqual(A: number[][], B: number[][]): boolean {
  for (let r = 0; r < 3; r += 1) {
    for (let c = 0; c < 3; c += 1) {
      if (roundToUnit(A[r][c]) !== roundToUnit(B[r][c])) return false;
    }
  }
  return true;
}

// Brute-force search over 4^3 Euler combinations in 90° steps.
function findEulerFromMatrix(M: number[][]): [0 | 90 | 180 | 270, 0 | 90 | 180 | 270, 0 | 90 | 180 | 270] | null {
  const angles: Array<0 | 90 | 180 | 270> = [0, 90, 180, 270];
  for (const rx of angles) {
    for (const ry of angles) {
      for (const rz of angles) {
        const candidate = eulerToMatrix(rx, ry, rz);
        if (matricesEqual(candidate, M)) {
          return [rx, ry, rz];
        }
      }
    }
  }
  return null;
}

function generateMockModel(prompt: string, agentType: string, seed: number, endpoint = "mock:basic"): LDrawPart[] {
  const variant = endpoint.slice("mock:".length).toLowerCase() || "basic";
  const baseColor = Math.abs(hashCode(`${agentType}|${prompt}`)) % 256;
  const height = ((seed % 5) + agentType.length) * 8;

  if (variant.startsWith("sphere")) {
    return [
      { ldraw_part: "3001.dat", color: baseColor, pos: [0, 0, 0], rot: [0, 0, 0] },
      { ldraw_part: "3003.dat", color: (baseColor + 4) % 256, pos: [0, height, 0], rot: [0, 90, 0] },
      { ldraw_part: "3001.dat", color: (baseColor + 8) % 256, pos: [0, height * 2, 0], rot: [0, 180, 0] },
    ];
  }

  if (variant.startsWith("tower")) {
    return Array.from({ length: 4 }, (_, idx) => ({
      ldraw_part: "3005.dat",
      color: (baseColor + idx * 7) % 256,
      pos: [0, idx * height, 0],
      rot: [0, 0, 0],
    }));
  }

  const offset = (hashCode(prompt) % 10) * 4;
  return [
    { ldraw_part: "3001.dat", color: baseColor, pos: [offset, 0, 0], rot: [0, 0, 0] },
    { ldraw_part: "3020.dat", color: (baseColor + 1) % 256, pos: [offset + 20, 0, 0], rot: [0, 0, 0] },
    { ldraw_part: "3004.dat", color: (baseColor + 2) % 256, pos: [offset + 10, height, 0], rot: [0, 0, 0] },
  ];
}

function validateModel(model: unknown, env: Env): { parts: LDrawPart[]; json: string } {
  const errors: Array<{ path: string; msg: string }> = [];

  if (!Array.isArray(model)) {
    throw new ApiError("VALIDATION_FAILED", "Invalid LDraw part array", 400, [{ path: "model", msg: "must be an array" }]);
  }

  const maxItemsRaw = Number(env.MODEL_MAX_ITEMS || "200");
  const maxItems = Number.isFinite(maxItemsRaw) && maxItemsRaw > 0 ? Math.floor(maxItemsRaw) : 200;
  const minItems = 1;
  const byteLimitRaw = Number(env.MODEL_MAX_BYTES || "1048576");
  const byteLimit = Number.isFinite(byteLimitRaw) && byteLimitRaw > 0 ? Math.floor(byteLimitRaw) : 1_048_576;
  const posMinRaw = Number(env.POS_MIN || "-10000");
  const posMaxRaw = Number(env.POS_MAX || "10000");
  const posMin = Number.isFinite(posMinRaw) ? posMinRaw : -10_000;
  const posMax = Number.isFinite(posMaxRaw) ? posMaxRaw : 10_000;
  const allowedRot = new Set([0, 90, 180, 270]);

  if (model.length < minItems) {
    errors.push({ path: "model", msg: `must contain at least ${minItems} part(s)` });
  }

  if (model.length > maxItems) {
    errors.push({ path: "model", msg: `must contain no more than ${maxItems} part(s)` });
  }

  const sanitized: LDrawPart[] = [];

  model.forEach((item, index) => {
    const pathPrefix = `[${index}]`;
    if (!item || typeof item !== "object") {
      errors.push({ path: pathPrefix, msg: "must be an object" });
      return;
    }

    const part = item as Record<string, unknown>;
    const ldraw = part.ldraw_part;
    const color = part.color;
    const pos = part.pos;
    const rot = part.rot;

    let isValid = true;

    if (typeof ldraw !== "string" || !/^[^\s]{1,64}\.dat$/i.test(ldraw)) {
      errors.push({ path: `${pathPrefix}.ldraw_part`, msg: "must match /^[^\\s]{1,64}\\.dat$/" });
      isValid = false;
    }

    if (typeof color !== "number" || !Number.isInteger(color) || color < 0 || color > 1023) {
      errors.push({ path: `${pathPrefix}.color`, msg: "must be integer between 0 and 1023" });
      isValid = false;
    }

    let posTuple: [number, number, number] | null = null;
    if (Array.isArray(pos) && pos.length === 3 && pos.every((value) => typeof value === "number" && Number.isFinite(value))) {
      const [x, y, z] = pos as number[];
      if (x < posMin || x > posMax || y < posMin || y > posMax || z < posMin || z > posMax) {
        errors.push({ path: `${pathPrefix}.pos`, msg: `each coordinate must be between ${posMin} and ${posMax}` });
        isValid = false;
      } else {
        posTuple = [x, y, z];
      }
    } else {
      errors.push({ path: `${pathPrefix}.pos`, msg: "must be an array of three numbers" });
      isValid = false;
    }

    let rotTuple: [0 | 90 | 180 | 270, 0 | 90 | 180 | 270, 0 | 90 | 180 | 270] | null = null;
    if (Array.isArray(rot) && rot.length === 3 && rot.every((value) => typeof value === "number" && allowedRot.has(value))) {
      const [rx, ry, rz] = rot as number[];
      rotTuple = [rx as 0 | 90 | 180 | 270, ry as 0 | 90 | 180 | 270, rz as 0 | 90 | 180 | 270];
    } else {
      errors.push({ path: `${pathPrefix}.rot`, msg: "must be an array of three values in {0,90,180,270}" });
      isValid = false;
    }

    if (isValid && posTuple && rotTuple) {
      sanitized.push({
        ldraw_part: ldraw as string,
        color: color as number,
        pos: posTuple,
        rot: rotTuple,
      });
    }
  });

  if (errors.length > 0) {
    throw new ApiError("VALIDATION_FAILED", "Invalid LDraw part array", 400, errors);
  }

  const sanitizedJson = JSON.stringify(sanitized);
  const jsonBytes = new TextEncoder().encode(sanitizedJson).length;
  if (jsonBytes > byteLimit) {
    throw new ApiError("VALIDATION_FAILED", "Invalid LDraw part array", 400, [
      { path: "model", msg: `serialized size must be <= ${byteLimit} bytes` },
    ]);
  }

  return { parts: sanitized, json: sanitizedJson };
}

async function designKey(prompt: string, agentType: string): Promise<string> {
  return sha256Hex(`${prompt.trim().toLowerCase()}|${agentType}`);
}

async function sha256Hex(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function makeRequestId(): string {
  return `${new Date().toISOString()}_${Math.random().toString(36).slice(2, 8)}`;
}

function hashCode(value: string): number {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0; // Convert to 32bit integer
  }
  return hash;
}

async function limitBodySize(request: Request, maxBytes: number): Promise<void> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > maxBytes) {
    throw new ApiError("PAYLOAD_TOO_LARGE", "Request body exceeds limit", 413, { maxBytes });
  }

  if (!contentLength) {
    const clone = request.clone();
    if (!clone.body) {
      return;
    }

    const reader = clone.body.getReader();
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value?.length ?? 0;
      if (total > maxBytes) {
        throw new ApiError("PAYLOAD_TOO_LARGE", "Request body exceeds limit", 413, { maxBytes });
      }
    }
  }
}
