/**
 * A2A-shaped wire types (emulating the Linux Foundation A2A protocol, v0.3
 * shapes). We do not invent a wire protocol: Agent Cards, Messages, Parts,
 * Tasks and JSON-RPC 2.0 methods follow A2A. Freight-specific content rides in
 * DataParts under a declared extension, and message signatures ride in
 * `metadata` — both are the sanctioned A2A extension points.
 */
import { canonicalize } from "./canonical";
import { importPublicKey, signJws, verifyJws, type KeyPair, type OkpJwk } from "./crypto";

export const A2A_PROTOCOL_VERSION = "0.3.0";
export const FREIGHT_EXTENSION_URI = "urn:freight-venue:ext:negotiation:v1";

// ---- Agent Card ----------------------------------------------------------

export interface AgentSkill {
  id: string;
  name: string;
  description: string;
  tags: string[];
  inputModes?: string[];
  outputModes?: string[];
}

export interface AgentCardSignature {
  protected: string; // b64url JWS protected header
  signature: string; // b64url signature
}

export interface AgentCard {
  protocolVersion: string;
  name: string;
  description: string;
  url: string;
  preferredTransport: "JSONRPC";
  version: string;
  provider: { organization: string; url?: string };
  capabilities: {
    streaming: boolean;
    pushNotifications: boolean;
    stateTransitionHistory: boolean;
    extensions?: { uri: string; description?: string; required?: boolean }[];
  };
  securitySchemes?: Record<string, unknown>;
  security?: Record<string, string[]>[];
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: AgentSkill[];
  /** Freight-venue extension: registry identity claimed by this agent's principal. */
  metadata?: Record<string, unknown>;
  signatures?: AgentCardSignature[];
}

/** Sign an Agent Card (JWS, detached payload = canonical card sans `signatures`). */
export function signAgentCard(card: AgentCard, kp: KeyPair): AgentCard {
  const { signatures: _s, ...unsigned } = card;
  const jws = signJws(unsigned, kp, { typ: "agent-card+jws", jwk: kp.publicJwk }, true);
  const [protectedHeader, , signature] = jws.split(".") as [string, string, string];
  return { ...unsigned, signatures: [{ protected: protectedHeader, signature }] };
}

export function verifyAgentCard(card: AgentCard, expectedKey?: OkpJwk): { ok: boolean; error?: string; jwk?: OkpJwk } {
  const sig = card.signatures?.[0];
  if (!sig) return { ok: false, error: "unsigned agent card" };
  const { signatures: _s, ...unsigned } = card;
  let header: { jwk?: OkpJwk; kid?: string };
  try {
    header = JSON.parse(Buffer.from(sig.protected, "base64url").toString("utf8"));
  } catch {
    return { ok: false, error: "malformed protected header" };
  }
  const jwk = expectedKey ?? header.jwk;
  if (!jwk) return { ok: false, error: "no key to verify with" };
  const res = verifyJws(`${sig.protected}..${sig.signature}`, importPublicKey(jwk), unsigned);
  return res.ok ? { ok: true, jwk } : { ok: false, error: res.error };
}

// ---- Message / Task ------------------------------------------------------

export type Role = "user" | "agent";

export interface TextPart { kind: "text"; text: string; metadata?: Record<string, unknown> }
export interface DataPart { kind: "data"; data: Record<string, unknown>; metadata?: Record<string, unknown> }
export interface FilePart { kind: "file"; file: { name?: string; mimeType?: string; bytes?: string; uri?: string }; metadata?: Record<string, unknown> }
export type Part = TextPart | DataPart | FilePart;

export interface Message {
  kind: "message";
  role: Role;
  parts: Part[];
  messageId: string;
  taskId?: string;
  contextId?: string;
  extensions?: string[];
  metadata?: Record<string, unknown>;
}

export type TaskState =
  | "submitted"
  | "working"
  | "input-required"
  | "completed"
  | "canceled"
  | "failed"
  | "rejected"
  | "auth-required";

export interface TaskStatus {
  state: TaskState;
  timestamp: string;
  message?: Message;
}

export interface Artifact {
  artifactId: string;
  name?: string;
  description?: string;
  parts: Part[];
  metadata?: Record<string, unknown>;
}

export interface Task {
  kind: "task";
  id: string;
  contextId: string;
  status: TaskStatus;
  artifacts?: Artifact[];
  history?: Message[];
  metadata?: Record<string, unknown>;
}

export const TERMINAL_STATES: TaskState[] = ["completed", "canceled", "failed", "rejected"];

// ---- JSON-RPC 2.0 --------------------------------------------------------

export interface JsonRpcRequest<P = unknown> {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params: P;
}
export interface JsonRpcError { code: number; message: string; data?: unknown }
export interface JsonRpcResponse<R = unknown> {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: R;
  error?: JsonRpcError;
}

export const RPC_ERR = {
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
  // A2A-defined
  TASK_NOT_FOUND: -32001,
  TASK_NOT_CANCELABLE: -32002,
  UNSUPPORTED_OPERATION: -32004,
  // freight-venue extension range
  VENUE_REFUSED: -32050,
} as const;

export interface SendMessageParams { message: Message; configuration?: { blocking?: boolean; acceptedOutputModes?: string[] } }
export interface TaskQueryParams { id: string; historyLength?: number }

export function rpcOk<R>(id: string | number | null, result: R): JsonRpcResponse<R> {
  return { jsonrpc: "2.0", id, result };
}
export function rpcErr(id: string | number | null, code: number, message: string, data?: unknown): JsonRpcResponse<never> {
  return { jsonrpc: "2.0", id, error: { code, message, data } };
}

export function dataPart(message: Message): Record<string, unknown> | undefined {
  const p = message.parts.find((x): x is DataPart => x.kind === "data");
  return p?.data;
}

/**
 * Signing surfaces. Two parties sign a Message at different times:
 *   - the originating agent signs before the venue touches it (excludes every
 *     venue-added field: metadata.sig, metadata.venueSig, metadata.venue)
 *   - the venue signs after verifying and enriching (excludes only metadata.venueSig)
 */
export function agentSigningSurface(m: Message): string {
  const { metadata, ...rest } = m;
  const { sig: _a, venueSig: _b, venue: _c, ...md } = (metadata ?? {}) as Record<string, unknown>;
  return canonicalize({ ...rest, metadata: md });
}
export function venueSigningSurface(m: Message): string {
  const { metadata, ...rest } = m;
  const { venueSig: _b, ...md } = (metadata ?? {}) as Record<string, unknown>;
  return canonicalize({ ...rest, metadata: md });
}
