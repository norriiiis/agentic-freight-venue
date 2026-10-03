/**
 * Outbound email: the proof-of-control challenge, and invitations.
 *
 * A seam, not an integration. `console` prints the message and is what a
 * closed pilot runs on while the operator is in the room; `http` posts to a
 * transactional provider. Nothing here retries — a challenge that does not
 * arrive is re-sent by a human, which is the correct amount of machinery for
 * the number of onboardings this will see.
 */
export interface Mail { to: string; subject: string; text: string }

export interface Mailer {
  readonly kind: string;
  send(m: Mail): Promise<{ ok: boolean; detail?: string }>;
}

export class ConsoleMailer implements Mailer {
  readonly kind = "console";
  constructor(private readonly log: (s: string) => void = console.log) {}
  async send(m: Mail) {
    this.log(`\n──── mail (not sent; APP_MAIL=console) ────\nTo: ${m.to}\nSubject: ${m.subject}\n\n${m.text}\n────\n`);
    return { ok: true, detail: "printed to the server log" };
  }
}

/** Resend or Postmark, whichever `APP_MAIL_PROVIDER` names. Both take one JSON POST. */
export class HttpMailer implements Mailer {
  readonly kind = "http";
  constructor(private readonly o: { provider: "resend" | "postmark"; token: string; from: string; fetchImpl?: typeof fetch }) {}
  async send(m: Mail) {
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

export function mailerFromEnv(env: NodeJS.ProcessEnv = process.env): Mailer {
  if ((env.APP_MAIL ?? "console") !== "http") return new ConsoleMailer();
  const provider = env.APP_MAIL_PROVIDER === "postmark" ? "postmark" : "resend";
  if (!env.APP_MAIL_TOKEN || !env.APP_MAIL_FROM) throw new Error("APP_MAIL=http needs APP_MAIL_TOKEN and APP_MAIL_FROM");
  return new HttpMailer({ provider, token: env.APP_MAIL_TOKEN, from: env.APP_MAIL_FROM });
}
