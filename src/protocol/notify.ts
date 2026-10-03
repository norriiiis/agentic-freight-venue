/**
 * Delivering something to a contact point that is not this system: an email
 * to the address on a public record, a code to whoever actually runs a
 * company. Shared by the venue (which challenges contact points itself) and
 * the hosted application (invitations).
 *
 * A seam, not an integration. Nothing here retries: a message that does not
 * arrive is re-sent by a human, which is the right amount of machinery for
 * the number of these a venue sends.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export interface Message { to: string; subject: string; text: string }
export interface Notifier {
  readonly kind: string;
  /** True only when the message was handed to something that can actually reach the recipient. */
  send(m: Message): Promise<{ ok: boolean; detail?: string }>;
}

/** Prints. For development, where the operator is the only recipient. */
export class ConsoleNotifier implements Notifier {
  readonly kind = "console";
  constructor(private readonly log: (s: string) => void = console.log) {}
  async send(m: Message) {
    this.log(`\n──── message (not sent; notifier=console) ────\nTo: ${m.to}\nSubject: ${m.subject}\n\n${m.text}\n────\n`);
    return { ok: true, detail: "printed to the server log" };
  }
}

/**
 * Appends to a file. Used in development and in tests so a challenge can be
 * read by whoever can read the server's disk — which is nobody over HTTP, and
 * is the point: a code that any caller could fetch proves nothing.
 */
export class FileNotifier implements Notifier {
  readonly kind = "file";
  constructor(private readonly path: string) { mkdirSync(dirname(path), { recursive: true }); }
  async send(m: Message) {
    appendFileSync(this.path, `${JSON.stringify({ at: new Date().toISOString(), ...m })}\n`);
    return { ok: true, detail: `appended to ${this.path}` };
  }
}

/** Resend or Postmark: one JSON POST each. */
export class HttpNotifier implements Notifier {
  readonly kind = "http";
  constructor(private readonly o: { provider: "resend" | "postmark"; token: string; from: string; fetchImpl?: typeof fetch }) {}
  async send(m: Message) {
    const f = this.o.fetchImpl ?? fetch;
    const [url, headers, body] = this.o.provider === "postmark"
      ? ["https://api.postmarkapp.com/email", { "content-type": "application/json", accept: "application/json", "x-postmark-server-token": this.o.token }, { From: this.o.from, To: m.to, Subject: m.subject, TextBody: m.text }]
      : ["https://api.resend.com/emails", { "content-type": "application/json", authorization: `Bearer ${this.o.token}` }, { from: this.o.from, to: [m.to], subject: m.subject, text: m.text }];
    try {
      const res = await f(url as string, { method: "POST", headers: headers as Record<string, string>, body: JSON.stringify(body) });
      return res.ok ? { ok: true } : { ok: false, detail: `HTTP ${res.status}` };
    } catch (e) {
      return { ok: false, detail: (e as Error).message };
    }
  }
}

/** `<prefix>NOTIFY` = console | file | http, with `<prefix>NOTIFY_*` for the rest. */
export function notifierFromEnv(prefix: string, env: NodeJS.ProcessEnv = process.env, filePath?: string): Notifier {
  const kind = env[`${prefix}NOTIFY`] ?? "console";
  if (kind === "file") return new FileNotifier(env[`${prefix}NOTIFY_FILE`] ?? filePath ?? ".data/messages.jsonl");
  if (kind === "http") {
    const token = env[`${prefix}NOTIFY_TOKEN`], from = env[`${prefix}NOTIFY_FROM`];
    if (!token || !from) throw new Error(`${prefix}NOTIFY=http needs ${prefix}NOTIFY_TOKEN and ${prefix}NOTIFY_FROM`);
    return new HttpNotifier({ provider: env[`${prefix}NOTIFY_PROVIDER`] === "postmark" ? "postmark" : "resend", token, from });
  }
  return new ConsoleNotifier();
}

/** `dispatch@prairiewind.example` → `di******@prairiewind.example`. What a challenge response may say about where it went. */
export function maskContact(to: string): string {
  const at = to.indexOf("@");
  if (at < 0) return `${to.slice(0, 2)}${"*".repeat(Math.max(0, to.length - 2))}`;
  const user = to.slice(0, at);
  return `${user.slice(0, 2)}${"*".repeat(Math.max(1, user.length - 2))}${to.slice(at)}`;
}
