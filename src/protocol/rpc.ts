/**
 * Minimal JSON-RPC 2.0 over HTTP(S), using node:http(s) and global fetch. No
 * framework dependencies. Transport hardening lives here so every process
 * (venue, registry, witness, agent) gets it the same way: optional TLS, a
 * token-bucket rate limit keyed by caller, a body-size cap, and an ops-token
 * gate for `/ops/*` routes.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { rpcErr, RPC_ERR, type JsonRpcRequest, type JsonRpcResponse } from "./a2a";

export type RpcHandler = (method: string, params: unknown, req: IncomingMessage) => Promise<unknown>;
export type HttpRoute = (req: IncomingMessage, body: unknown) => Promise<{ status: number; body: unknown }>;

export class RpcRefusal extends Error {
  constructor(public readonly code: number, message: string, public readonly data?: unknown) {
    super(message);
  }
}

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

async function readJson(req: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > maxBytes) throw new BodyTooLarge(size);
    chunks.push(c as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}
class BodyTooLarge extends Error {
  constructor(public readonly size: number) { super(`body exceeds ${MAX_BODY_BYTES} bytes`); }
}

/** Token bucket per key: `capacity` burst, `refillPerSec` sustained. */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number; at: number }>();
  constructor(readonly capacity: number, readonly refillPerSec: number) {}
  allow(key: string, now = Date.now()): boolean {
    const b = this.buckets.get(key) ?? { tokens: this.capacity, at: now };
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.at) / 1000) * this.refillPerSec);
    b.at = now;
    if (b.tokens < 1) { this.buckets.set(key, b); return false; }
    b.tokens -= 1;
    this.buckets.set(key, b);
    if (this.buckets.size > 10_000) for (const [k, v] of this.buckets) if (now - v.at > 60_000) this.buckets.delete(k);
    return true;
  }
}

/** Who is calling, for rate limiting: the bearer/signature if any, else the peer address. */
export function callerKey(req: IncomingMessage): string {
  const auth = req.headers.authorization;
  const a = Array.isArray(auth) ? auth[0] : auth;
  return a ? `auth:${a.slice(0, 64)}` : `ip:${req.socket.remoteAddress ?? "?"}`;
}

const constantEq = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

function send(res: ServerResponse, status: number, body: unknown) {
  // A string body is served as text (Prometheus metrics); everything else as JSON.
  const text = typeof body === "string";
  const data = text ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": text ? "text/plain; version=0.0.4; charset=utf-8" : "application/json", "content-length": Buffer.byteLength(data) });
  res.end(data);
}

export interface ServerSpec {
  /** JSON-RPC endpoint path (A2A). */
  rpcPath: string;
  rpc: RpcHandler;
  /** Plain HTTP routes, e.g. /.well-known/agent-card.json and sim-only control endpoints. */
  routes: Record<string, HttpRoute>; // key: "GET /path" | "POST /path"
  /** TLS: paths to a PEM certificate and key. Absent = plain HTTP (loopback, or behind a terminating proxy). */
  tls?: { certPath: string; keyPath: string };
  /** Requests per second per caller (burst = 2×). Absent = unlimited. */
  rateLimit?: { perSecond: number };
  /** Bearer token required on every `/ops/*` route. Absent = those routes are refused outright. */
  opsToken?: string;
  /** Bind address; default loopback. */
  host?: string;
}

export function startServer(port: number, spec: ServerSpec): Promise<Server> {
  const limiter = spec.rateLimit ? new RateLimiter(Math.max(2, spec.rateLimit.perSecond * 2), spec.rateLimit.perSecond) : undefined;
  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const key = `${req.method} ${url.pathname}`;
      if (limiter && !limiter.allow(callerKey(req))) {
        res.setHeader("retry-after", "1");
        return send(res, 429, url.pathname === spec.rpcPath ? rpcErr(null, RPC_ERR.INTERNAL, "rate limited") : { error: "rate limited" });
      }
      if (url.pathname.startsWith("/ops/")) {
        const a = req.headers.authorization;
        const token = (Array.isArray(a) ? a[0] : a)?.replace(/^Bearer\s+/i, "") ?? "";
        if (!spec.opsToken || !constantEq(token, spec.opsToken)) return send(res, 401, { error: "ops token required" });
      }
      if (req.method === "POST" && url.pathname === spec.rpcPath) {
        let body: JsonRpcRequest;
        try {
          body = (await readJson(req)) as JsonRpcRequest;
        } catch {
          return send(res, 200, rpcErr(null, RPC_ERR.PARSE, "parse error"));
        }
        if (!body || body.jsonrpc !== "2.0" || typeof body.method !== "string") {
          return send(res, 200, rpcErr(body?.id ?? null, RPC_ERR.INVALID_REQUEST, "invalid request"));
        }
        try {
          const result = await spec.rpc(body.method, body.params, req);
          return send(res, 200, { jsonrpc: "2.0", id: body.id, result } satisfies JsonRpcResponse);
        } catch (e) {
          if (e instanceof RpcRefusal) return send(res, 200, rpcErr(body.id, e.code, e.message, e.data));
          const msg = e instanceof Error ? e.message : String(e);
          return send(res, 200, rpcErr(body.id, RPC_ERR.INTERNAL, msg));
        }
      }
      // Exact match first; then a prefix route ("GET /bundle/*") for paths that carry an id.
      const route = spec.routes[key] ?? Object.entries(spec.routes).find(([k]) => k.endsWith("/*") && key.startsWith(k.slice(0, -1)))?.[1];
      if (!route) return send(res, 404, { error: "not found" });
      const body = req.method === "POST" ? await readJson(req) : undefined;
      const out = await route(req, body);
      return send(res, out.status, out.body);
    } catch (e) {
      if (e instanceof BodyTooLarge) return send(res, 413, { error: e.message });
      return send(res, 500, { error: e instanceof Error ? e.message : String(e) });
    }
  };
  const server = spec.tls ? createTlsServer({ cert: readFileSync(spec.tls.certPath), key: readFileSync(spec.tls.keyPath) }, handler) : createServer(handler);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, spec.host ?? "127.0.0.1", () => resolve(server as Server));
  });
}

export async function rpcCall<R = unknown>(url: string, method: string, params: unknown, headers: Record<string, string> = {}): Promise<JsonRpcResponse<R>> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: randomUUID(), method, params } satisfies JsonRpcRequest),
  });
  return (await res.json()) as JsonRpcResponse<R>;
}

export async function httpGet<R = unknown>(url: string): Promise<R> {
  const res = await fetch(url);
  return (await res.json()) as R;
}
export async function httpPost<R = unknown>(url: string, body: unknown): Promise<R> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return (await res.json()) as R;
}

export async function waitForHealth(url: string, timeoutMs = 8000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`service at ${url} did not become healthy in ${timeoutMs}ms`);
}
