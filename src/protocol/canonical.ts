/**
 * Deterministic JSON serialization (JCS-like, RFC 8785 in spirit).
 *
 * Every signature and hash in this system is computed over the output of
 * `canonicalize()`, so two parties who hold the same logical object always
 * compute the same bytes. Keys are sorted recursively; `undefined` values are
 * dropped; no whitespace.
 */
import { createHash } from "node:crypto";

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("canonicalize: non-finite number");
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "undefined":
      throw new Error("canonicalize: undefined at top level");
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => (v === undefined ? "null" : canonicalize(v))).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
    }
    default:
      throw new Error(`canonicalize: unsupported type ${typeof value}`);
  }
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** sha256 over the canonical form of an object, hex-encoded. */
export function hashObject(value: unknown): string {
  return sha256Hex(canonicalize(value));
}
