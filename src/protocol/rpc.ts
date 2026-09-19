/**
 * Minimal JSON-RPC 2.0 over HTTP, using node:http and global fetch. No
 * framework dependencies.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { rpcErr, RPC_ERR, type JsonRpcRequest, type JsonRpcResponse } from "./a2a";

export type RpcHandler = (method: string, params: unknown, req: IncomingMessage) => Promise<unknown>;
export type HttpRoute = (req: IncomingMessage, body: unknown) => Promise<{ status: number; body: unknown }>;

export class RpcRefusal extends Error {
  constructor(public readonly code: number, message: string, public readonly data?: unknown) {
    super(message);
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}

function send(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(data) });
  res.end(data);
}

export interface ServerSpec {
  /** JSON-RPC endpoint path (A2A). */
  rpcPath: string;
  rpc: RpcHandler;
  /** Plain HTTP routes, e.g. /.well-known/agent-card.json and sim-only control endpoints. */
  routes: Record<string, HttpRoute>; // key: "GET /path" | "POST /path"
}

export function startServer(port: number, spec: ServerSpec): Promise<Server> {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const key = `${req.method} ${url.pathname}`;
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
      const route = spec.routes[key];
      if (!route) return send(res, 404, { error: "not found" });
      const body = req.method === "POST" ? await readJson(req) : undefined;
      const out = await route(req, body);
      return send(res, out.status, out.body);
    } catch (e) {
      return send(res, 500, { error: e instanceof Error ? e.message : String(e) });
    }
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

export async function rpcCall<R = unknown>(url: string, method: string, params: unknown): Promise<JsonRpcResponse<R>> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
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
