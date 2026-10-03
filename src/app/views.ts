/**
 * The HTML. Server-rendered, no client framework, no build step: this is an
 * operations console that a dispatcher reads and a compliance officer prints,
 * and every number on it has a source behind it.
 *
 * The visual language is the one from design/console — warm paper, three
 * reserved status colours, a serif for verdicts and a mono for anything a
 * machine produced. Styles live in one stylesheet served at /app.css rather
 * than inline, because here they are shared across pages.
 */
export const esc = (s: unknown): string =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

export const money = (n: number | undefined | null, dp = 0): string =>
  n === undefined || n === null ? "—" : `$${n.toLocaleString("en-US", { minimumFractionDigits: dp, maximumFractionDigits: dp })}`;

export const shortId = (s: string | undefined | null, n = 12): string => (s ? (s.length > n ? `${s.slice(0, n)}…` : s) : "—");

export const when = (iso: string | undefined | null): string => {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const mins = (Date.now() - d.getTime()) / 60_000;
  if (mins < 1) return "just now";
  if (mins < 60) return `${Math.floor(mins)}m ago`;
  if (mins < 60 * 24) return `${Math.floor(mins / 60)}h ago`;
  return d.toISOString().slice(0, 10);
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";
export function chip(text: string, tone: Tone = "neutral"): string {
  const c: Record<Tone, string> = { good: "chip-good", warn: "chip-warn", bad: "chip-bad", neutral: "chip-neutral", info: "chip-info" };
  return `<span class="chip ${c[tone]}">${esc(text)}</span>`;
}

export function meter(fraction: number, tone: Tone = "neutral"): string {
  const pct = Math.max(0, Math.min(1, fraction)) * 100;
  return `<div class="meter"><div class="meter-fill meter-${tone}" style="width:${pct.toFixed(1)}%"></div></div>`;
}

export function tile(o: { label: string; value: string; sub?: string; tone?: Tone; meter?: number }): string {
  return `<div class="tile">
    <div class="tile-label">${esc(o.label)}</div>
    <div class="tile-value mono${o.tone ? ` t-${o.tone}` : ""}">${esc(o.value)}</div>
    ${o.sub ? `<div class="tile-sub">${esc(o.sub)}</div>` : ""}
    ${o.meter !== undefined ? meter(o.meter, o.tone) : ""}
  </div>`;
}

export interface ShellNav { href: string; label: string; count?: number; active?: boolean; tone?: Tone }
export interface ShellOpts {
  title: string;
  heading?: string;
  headingMeta?: string;
  actions?: string;
  org?: { name: string; usdot?: string; mc?: string | null; role: string };
  orgSwitcher?: { id: string; name: string; active: boolean }[];
  nav: ShellNav[];
  agent?: { agentId: string; status: string; mandateExpiresAt?: string; note?: string };
  staff?: boolean;
  flash?: { tone: Tone; text: string };
  /** The one disclosure this product owes every user, on every page. */
  disclosure: string;
  body: string;
}

export function shell(o: ShellOpts): string {
  const nav = o.nav.map((n) => `<a href="${esc(n.href)}" class="${n.active ? "nav-on" : ""}">${n.active ? '<span class="dot"></span>' : ""}<span>${esc(n.label)}</span>${n.count !== undefined ? `<span class="nav-count${n.tone ? ` t-${n.tone}` : ""}">${n.count}</span>` : ""}</a>`).join("");
  const switcher = o.orgSwitcher && o.orgSwitcher.length > 1
    ? `<form method="post" action="/switch-org" class="switcher"><select name="orgId" onchange="this.form.submit()" aria-label="Organisation">${o.orgSwitcher.map((s) => `<option value="${esc(s.id)}"${s.active ? " selected" : ""}>${esc(s.name)}</option>`).join("")}</select></form>`
    : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(o.title)} — Interchange</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Newsreader:opsz,wght@6..72,400;6..72,500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/app.css">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' fill='%231A1917'/%3E%3Cpath d='M4 11.5V4.5M8 11.5V4.5M12 11.5V4.5' stroke='%23F7F5F0' stroke-width='1.6'/%3E%3C/svg%3E">
</head>
<body class="app">
<div class="rail">
  <div class="rail-top">
    <div class="wordmark">INTERCHANGE</div>
    <div class="wordmark-sub">${o.staff ? "operations" : "freight transaction venue"}</div>
  </div>
  ${o.org ? `<div class="org-card">
    <div class="org-name">${esc(o.org.name)}</div>
    <div class="mono org-ids">${o.org.usdot ? `USDOT ${esc(o.org.usdot)}` : "no entity yet"}${o.org.mc ? ` · ${esc(o.org.mc)}` : ""}</div>
    ${switcher}
  </div>` : ""}
  <nav class="rail-nav">${nav}</nav>
  <div class="rail-foot">
    ${o.agent ? `<div class="agent-status">
      <div class="agent-line"><span class="dot ${o.agent.status === "LIVE" ? "dot-good" : o.agent.status === "FAILED" ? "dot-bad" : "dot-warn"}"></span><span class="mono">${esc(o.agent.agentId)}</span></div>
      <div class="agent-note">${esc(o.agent.note ?? o.agent.status)}${o.agent.mandateExpiresAt ? `<br>Mandate to ${esc(o.agent.mandateExpiresAt.slice(0, 10))}` : ""}</div>
    </div>` : ""}
    <form method="post" action="/logout"><button type="submit" class="linkish">Sign out</button></form>
  </div>
</div>
<div class="main">
  <header class="topbar">
    <h1>${esc(o.heading ?? o.title)}</h1>
    ${o.headingMeta ? `<span class="mono meta">${esc(o.headingMeta)}</span>` : ""}
    <div class="spacer"></div>
    ${o.actions ?? ""}
  </header>
  <div class="content">
    ${o.flash ? `<div class="flash flash-${o.flash.tone}">${esc(o.flash.text)}</div>` : ""}
    ${o.body}
    <p class="disclosure">${esc(o.disclosure)}</p>
  </div>
</div>
</body>
</html>`;
}

/** The pages a signed-out visitor sees: one column, no rail. */
export function plain(o: { title: string; body: string; flash?: { tone: Tone; text: string } }): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(o.title)} — Interchange</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Newsreader:opsz,wght@6..72,400;6..72,500&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/app.css">
</head>
<body class="plain">
<main class="card-narrow">
  <div class="wordmark dark">INTERCHANGE</div>
  ${o.flash ? `<div class="flash flash-${o.flash.tone}">${esc(o.flash.text)}</div>` : ""}
  ${o.body}
</main>
</body>
</html>`;
}

export const CSS = `
*{box-sizing:border-box}
body{margin:0;background:#F7F5F0;color:#171614;font-family:'Space Grotesk',ui-sans-serif,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
a{color:#17594A}a:hover{color:#0E3E33}
.mono,.m{font-family:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;font-variant-ligatures:none}
.serif{font-family:Newsreader,ui-serif,Georgia,serif}
h1,h2,h3{margin:0}
button,input,select,textarea{font:inherit;color:inherit}
.app{display:flex;min-height:100vh}
.rail{width:224px;flex-shrink:0;background:#1A1917;color:#F7F5F0;display:flex;flex-direction:column;padding:22px 0 16px;position:sticky;top:0;height:100vh}
.rail-top{padding:0 20px 18px}
.wordmark{font-size:14px;font-weight:600;letter-spacing:.16em}
.wordmark.dark{color:#171614;margin-bottom:22px}
.wordmark-sub{font-size:10px;color:#8B857A;letter-spacing:.06em;margin-top:4px}
.org-card{margin:0 12px 16px;padding:12px;background:#262421;border-radius:4px}
.org-name{font-size:12px;font-weight:500;line-height:1.3}
.org-ids{font-size:10px;color:#A8A296;margin-top:6px}
.switcher{margin-top:9px}
.switcher select{width:100%;background:#1A1917;color:#F7F5F0;border:1px solid #3A3630;border-radius:3px;font-size:11px;padding:5px 6px}
.rail-nav{display:flex;flex-direction:column;gap:1px;padding:0 12px}
.rail-nav a{display:flex;align-items:center;gap:8px;padding:9px 10px 9px 23px;border-radius:3px;color:#A8A296;text-decoration:none;font-size:13px}
.rail-nav a:hover{color:#F7F5F0;background:#242120}
.rail-nav a.nav-on{padding-left:10px;background:#2E2B27;color:#F7F5F0;font-weight:500}
.rail-nav .nav-count{margin-left:auto;font-family:'IBM Plex Mono',monospace;font-size:11px}
.dot{width:5px;height:5px;border-radius:50%;background:#4FAF93;flex-shrink:0}
.dot-good{background:#4FAF93}.dot-warn{background:#D8A657}.dot-bad{background:#E09A82}
.rail-foot{margin-top:auto;padding:12px;border-top:1px solid #332F2B;margin-left:12px;margin-right:12px}
.agent-status{margin-bottom:10px}
.agent-line{display:flex;align-items:center;gap:7px;font-size:11px}
.agent-note{font-size:11px;color:#8B857A;line-height:1.5;margin-top:5px}
.linkish{background:none;border:none;padding:0;color:#8B857A;font-size:11px;cursor:pointer;text-decoration:underline}
.linkish:hover{color:#F7F5F0}
.main{flex-grow:1;min-width:0;display:flex;flex-direction:column}
.topbar{height:58px;flex-shrink:0;border-bottom:1px solid #E3DFD5;display:flex;align-items:center;gap:14px;padding:0 28px;background:#fff;position:sticky;top:0;z-index:5}
.topbar h1{font-size:16px;font-weight:600}
.meta{font-size:11px;color:#6B6459}
.spacer{flex-grow:1}
.content{padding:22px 28px 56px;max-width:1500px}
.plain{display:flex;align-items:center;justify-content:center;padding:48px 20px;min-height:100vh}
.card-narrow{width:100%;max-width:440px;background:#fff;border:1px solid #E3DFD5;border-radius:5px;padding:30px 32px}
.grid-4{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.cols{display:grid;grid-template-columns:minmax(0,1fr) 400px;gap:20px;margin-top:20px}
@media (max-width:1180px){.cols{grid-template-columns:minmax(0,1fr)}}
.stack{display:flex;flex-direction:column;gap:18px}
.card{background:#fff;border:1px solid #E3DFD5;border-radius:4px;padding:18px 20px}
.card h2,.card h3{font-size:13px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#3D382F}
.card .lede{font-size:12px;color:#6B6459;margin:6px 0 14px;line-height:1.5}
.tile{background:#fff;border:1px solid #E3DFD5;border-radius:4px;padding:14px 16px}
.tile-label{font-size:11px;color:#6B6459;letter-spacing:.04em;text-transform:uppercase}
.tile-value{font-size:26px;font-weight:500;margin:6px 0 2px}
.tile-sub{font-size:11px;color:#6B6459}
.meter{height:6px;background:#E3DFD5;border-radius:3px;margin-top:10px;overflow:hidden}
.meter-fill{height:6px;border-radius:3px;background:#171614}
.meter-warn{background:#8A5A18}.meter-bad{background:#9E3B24}.meter-good{background:#17594A}
.t-good{color:#17594A}.t-warn{color:#8A5A18}.t-bad{color:#9E3B24}.t-info{color:#33406B}
.chip{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.05em;padding:3px 7px;border-radius:2px;white-space:nowrap}
.chip-good{color:#17594A;background:#E6EFEA}.chip-warn{color:#8A5A18;background:#F6EDDD}
.chip-bad{color:#fff;background:#9E3B24}.chip-neutral{color:#3D382F;background:#EFEBE2}.chip-info{color:#33406B;background:#E8EAF2}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #E3DFD5;border-radius:4px}
th{text-align:left;font-size:11px;font-weight:500;color:#6B6459;padding:9px 14px;border-bottom:1px solid #E3DFD5}
td{font-size:12px;padding:11px 14px;border-bottom:1px solid #EFEBE2}
tbody tr:last-child td{border-bottom:none}
.num{text-align:right}
.btn{display:inline-block;border:1px solid #171614;background:#171614;color:#F7F5F0;font-size:13px;font-weight:500;padding:9px 14px;border-radius:3px;cursor:pointer;text-decoration:none}
.btn:hover{background:#000;color:#fff}
.btn-quiet{border:1px solid #CFC9BB;background:#fff;color:#171614;font-weight:400}
.btn-quiet:hover{background:#F7F5F0;color:#171614}
.btn[disabled]{border-color:#CFC9BB;background:#EFEBE2;color:#8B857A;cursor:not-allowed}
.btn-sm{font-size:11px;padding:5px 10px}
label{display:block;font-size:12px;font-weight:500;margin-bottom:5px}
.hint{font-size:11px;color:#6B6459;line-height:1.5;margin:5px 0 0}
input[type=text],input[type=email],input[type=password],input[type=number],textarea,select{width:100%;border:1px solid #CFC9BB;border-radius:3px;padding:9px 10px;font-size:13px;background:#fff}
input:focus,textarea:focus,select:focus{outline:2px solid #17594A;outline-offset:-1px}
.field{margin-bottom:16px}
.row{display:flex;gap:12px;align-items:flex-end}
.row>*{flex:1}
.flash{padding:11px 14px;border-radius:3px;font-size:13px;margin-bottom:18px;line-height:1.5}
.flash-good{background:#E6EFEA;color:#145243}.flash-bad{background:#F7E9E4;color:#8A3320}
.flash-warn{background:#F6EDDD;color:#7A4F14}.flash-info{background:#E8EAF2;color:#2C3659}.flash-neutral{background:#EFEBE2;color:#3D382F}
.disclosure{margin:34px 0 0;font-size:11px;line-height:1.6;color:#6B6459;max-width:88ch;border-top:1px solid #E3DFD5;padding-top:14px}
.steps{display:flex;flex-direction:column;gap:0}
.step{display:grid;grid-template-columns:30px minmax(0,1fr);gap:14px;padding:16px 0;border-top:1px solid #EFEBE2}
.step:first-child{border-top:none}
.step-n{width:24px;height:24px;border-radius:50%;border:1px solid #CFC9BB;display:flex;align-items:center;justify-content:center;font-size:11px;color:#6B6459}
.step-done .step-n{background:#17594A;border-color:#17594A;color:#fff}
.step-now .step-n{background:#171614;border-color:#171614;color:#fff}
.step h3{font-size:14px;font-weight:600;text-transform:none;letter-spacing:0;color:#171614}
.step p{font-size:12px;line-height:1.55;color:#6B6459;margin:5px 0 0}
.step-body{margin-top:14px}
.kv{display:grid;grid-template-columns:150px minmax(0,1fr);row-gap:8px;column-gap:12px;margin:0}
.kv dt{font-size:11px;color:#6B6459}
.kv dd{margin:0;font-size:12px}
.wire{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:13px 0;border-top:1px solid #E3DFD5}
.wire:first-child{border-top:none}
.wire-head{display:flex;align-items:baseline;gap:9px;flex-wrap:wrap}
.wire-rate{margin-left:auto;font-family:'IBM Plex Mono',monospace;font-size:15px;font-weight:500}
.wire-sub{font-size:10px;color:#6B6459;margin-top:5px;line-height:1.6;font-family:'IBM Plex Mono',monospace}
.verdict{font-family:Newsreader,ui-serif,Georgia,serif;font-size:32px;font-weight:400;line-height:1.25;margin:10px 0 0}
.facts{display:flex;flex-wrap:wrap;margin-top:18px;border-top:1px solid #E3DFD5;padding-top:15px;gap:0}
.fact{padding:0 24px;border-right:1px solid #E3DFD5}
.fact:first-child{padding-left:0}.fact:last-child{border-right:none}
.fact-k{font-size:11px;color:#6B6459}
.fact-v{font-family:'IBM Plex Mono',monospace;font-size:13px;margin-top:4px}
.empty{padding:34px 20px;text-align:center;color:#6B6459;font-size:13px;background:#fff;border:1px dashed #CFC9BB;border-radius:4px}
.muted{color:#6B6459}
.small{font-size:11px}
`;
