import { html, raw } from 'hono/html';
import type { Match } from './check';
import type { Filters, getThreat, SourceStatus, ThreatOut } from './db';
import type { Unresolved } from './parsers';
import { ECOSYSTEMS, KINDS, type Kind } from './types';

type ThreatDetail = NonNullable<Awaited<ReturnType<typeof getThreat>>>;
export interface Site {
  name: string;
  url: string;
  repo: string;
}

/** Prefilled GitHub issue form (.github/ISSUE_TEMPLATE/report.yml). */
const reportUrl = (site: Site, threatId?: string) =>
  `${site.repo}/issues/new?template=report.yml${threatId ? `&threat_id=${encodeURIComponent(threatId)}&title=${encodeURIComponent(`Report: ${threatId}`)}` : ''}`;

/** Cracked padlock: brand orange on the header color. */
export const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#101820"/><path d="M21 28v-6a11 11 0 0 1 22 0v6" fill="none" stroke="#FB923C" stroke-width="5" stroke-linecap="round"/><rect x="14" y="28" width="36" height="25" rx="5" fill="#FB923C"/><path d="M33 31l-5 8 6 3-4 8" fill="none" stroke="#101820" stroke-width="3.5" stroke-linejoin="round" stroke-linecap="round"/></svg>`;

const FONTS =
  'https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@75..100,500..800&family=Public+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap';

// Palette and type from the design mockup; dark values follow prefers-color-scheme.
const CSS = `
:root{--ground:#F3F5F6;--panel:#FFFFFF;--ink:#101820;--inv-fg:#FFFFFF;--ink-2:#2D3740;--ink-3:#3E4A53;--muted:#56626C;--line:#D5DCE1;--line-2:#C3CCD3;--soft:#EEF1F3;--subtle:#F8FAFB;--dash:#A7B3BC;--link:#1D4ED8;--link-hover:#1E3A8A;--ok:#15803D;--act:#C2410C;--act-tint:#FFF4ED;--act-border:#F3C4A6;--act-label:#7C2D12;--act-text:#C2410C;--watch-bg:#FDF1D8;--watch:#8A5A00;--header:#101820;--code-bg:#101820;--code-fg:#E5EAEE;
--display:'Archivo',system-ui,sans-serif;--body:'Public Sans',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace}
@media (prefers-color-scheme:dark){:root{--ground:#0D1316;--panel:#151C21;--ink:#E6ECEF;--inv-fg:#0D1316;--ink-2:#C5CFD5;--ink-3:#AEB9C0;--muted:#8E9BA4;--line:#26313A;--line-2:#3A4750;--soft:#1E272E;--subtle:#10171B;--dash:#4A5862;--link:#8AB4FF;--link-hover:#B9D1FF;--ok:#4ADE80;--act-tint:#2A1810;--act-border:#7C3A16;--act-label:#FDBA8C;--act-text:#FB923C;--watch-bg:#3A2C0E;--watch:#E8B04B;--header:#070B0D;--code-bg:#0A0F12;--code-fg:#D5DEE3;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:15px/1.5 var(--body)}
a{color:var(--link)}a:hover{color:var(--link-hover)}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.mono{font-family:var(--mono)}
.wrap{max-width:1240px;margin:0 auto;padding-left:24px;padding-right:24px}
.top{background:var(--header);color:#F3F5F6}
.top .wrap{padding-top:14px;padding-bottom:14px;display:flex;flex-wrap:wrap;align-items:center;gap:12px 28px}
.brand{color:#F3F5F6;text-decoration:none;font:800 22px var(--display);font-stretch:80%;letter-spacing:-.01em}
.brand span{color:#FB923C}
.top nav{display:flex;flex-wrap:wrap;gap:4px 20px;font-size:14px}
.top nav a{color:#C9D2D9;text-decoration:none}
.top nav a[aria-current]{color:#fff;font-weight:600;border-bottom:2px solid #FB923C;padding-bottom:2px}
.top .free{margin-left:auto;font-size:13px;color:#C9D2D9}
.status{border-bottom:1px solid var(--line);background:var(--panel)}
.status .wrap{padding-top:10px;padding-bottom:10px;display:flex;flex-wrap:wrap;gap:6px 24px;font:12px var(--mono);color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);margin-right:6px}
.dot.stale{background:var(--act)}
main.wrap{padding-top:36px;padding-bottom:64px;display:flex;flex-direction:column;gap:28px}
h1{margin:0;font:800 46px/1.02 var(--display);font-stretch:78%;letter-spacing:-.015em}
.lede{margin:0;max-width:62ch;color:var(--ink-3);font-size:16px}
.hero{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:20px 40px}
.hero>div:first-child{flex:1 1 520px;min-width:0;display:flex;flex-direction:column;gap:8px}
.hero>div:last-child{flex:0 1 420px;min-width:0;display:flex;flex-direction:column;gap:10px}
.btns{display:flex;flex-wrap:wrap;gap:8px}
.btn{display:inline-flex;align-items:center;min-height:40px;padding:0 14px;border:1px solid var(--line-2);border-radius:6px;background:var(--panel);color:var(--ink);text-decoration:none;font:500 14px var(--body);cursor:pointer}
.btn.dark{border:0;background:var(--ink);color:var(--inv-fg);font-weight:600}
.btn.act{border:0;background:#C2410C;color:#fff;font-weight:700;min-height:44px;padding:0 22px}
.label{font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.copy{display:flex;gap:8px}
.copy input{flex:1 1 auto;min-width:0;min-height:40px;padding:0 12px;border:1px solid var(--line-2);border-radius:6px;background:var(--panel);font:13px var(--mono);color:var(--ink)}
.cols{display:flex;flex-wrap:wrap;align-items:flex-start;gap:28px}
.side{flex:1 1 220px;max-width:280px;min-width:0;display:flex;flex-direction:column;gap:22px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px}
.side fieldset{border:0;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
.side legend{padding:0;margin-bottom:8px}
.check{display:flex;align-items:center;gap:8px;font-size:14px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{position:relative;display:inline-flex;align-items:center;min-height:32px;padding:0 10px;border-radius:16px;font-size:13px;background:var(--panel);color:var(--ink-2);border:1px solid var(--line-2);cursor:pointer}
.chip input{position:absolute;opacity:0;width:1px;height:1px}
.chip:has(input:checked){background:var(--ink);color:var(--inv-fg);border-color:var(--ink)}
.chip:has(input:focus-visible){outline:2px solid var(--link);outline-offset:2px}
.seg{display:flex;gap:6px}
.seg .chip{flex:1;justify-content:center;border-radius:6px;min-height:36px}
.swatch{width:10px;height:10px;flex:0 0 auto}
.list{flex:999 1 560px;min-width:0;display:flex;flex-direction:column;gap:14px}
.list-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:8px}
h2.sec{margin:0;font:700 20px var(--display);font-stretch:85%}
.card{display:flex;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.bar{flex:0 0 34px;writing-mode:vertical-rl;transform:rotate(180deg);display:flex;align-items:center;justify-content:center;font:800 12px var(--display);font-stretch:85%;letter-spacing:.12em}
.bar.t1{background:#C2410C;color:#fff}
.bar.t2{background:var(--watch-bg);color:var(--watch);border-left:1px solid var(--watch)}
.bar.t3{background:var(--soft);color:var(--muted)}
.card-body{flex:1 1 auto;min-width:0;padding:18px 22px;display:flex;flex-direction:column;gap:8px}
.meta{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:var(--muted)}
.kind{font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.card h3{margin:0;font:700 21px/1.2 var(--display);font-stretch:88%}
.card h3 a{color:var(--ink);text-decoration:none}.card h3 a:hover{text-decoration:underline}
.card p{margin:0;max-width:72ch;color:var(--ink-2)}
.flags{display:flex;flex-wrap:wrap;gap:6px;padding-top:2px}
.flag{font-size:12px;padding:3px 8px;border-radius:4px;background:var(--soft);color:var(--ink-2)}
.flag.hot{background:var(--act-tint);color:var(--act-label)}
.foot{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 20px;padding-top:8px;border-top:1px solid var(--soft);font-size:12px;color:var(--muted)}
.bulk{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 20px;padding:14px 18px;border:1px dashed var(--dash);border-radius:8px;color:var(--ink-3);font-size:14px}
.bulk strong{color:var(--ink)}
.small{margin:0;font-size:12px;color:var(--muted)}
.empty{padding:28px;text-align:center;background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--ink-3)}
.crumb{display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px;font-size:13px;color:var(--muted)}
.badge{display:inline-flex;align-items:center;min-height:28px;padding:0 10px;font:800 12px var(--display);font-stretch:85%;letter-spacing:.12em}
.badge.t1{background:#C2410C;color:#fff}.badge.t2{background:var(--watch-bg);color:var(--watch)}.badge.t3{background:var(--soft);color:var(--muted)}
h1.detail{max-width:28ch;font-size:44px;line-height:1.04}
.main-col{flex:999 1 600px;min-width:0;display:flex;flex-direction:column;gap:24px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:24px}
.panel h2.act{margin:0 0 8px;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--act-text)}
.panel p{margin:0}
.table-box{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}
table{width:100%;min-width:560px;border-collapse:collapse;font-size:14px}
th{padding:12px 16px;text-align:left;font-weight:600;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line)}
td{padding:14px 16px;border-top:1px solid var(--soft);vertical-align:top}
td.v{font:13px var(--mono)}td.safe{color:var(--ok);font-weight:500}
.timeline{list-style:none;margin:0;padding:0;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.timeline li{display:flex;flex-wrap:wrap;gap:4px 20px;padding:14px 18px;border-top:1px solid var(--soft)}
.timeline li:first-child{border-top:0}
.timeline .when{flex:0 0 150px;font:13px var(--mono);color:var(--muted)}
.timeline .what{flex:1 1 300px;min-width:0}
.aside{flex:1 1 280px;max-width:340px;min-width:0;display:flex;flex-direction:column;gap:16px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px;display:flex;flex-direction:column;gap:12px}
.box h2{margin:0}
.ids{display:flex;flex-direction:column;gap:6px;font:13px var(--mono);overflow-wrap:anywhere}
dl.stats{margin:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 12px;font-size:14px}
dl.stats dt{color:var(--muted)}dl.stats dd{margin:0;font-weight:600;font-variant-numeric:tabular-nums}
.block-btn{display:flex;align-items:center;justify-content:center;min-height:48px;border-radius:6px;background:var(--ink);color:var(--inv-fg);text-decoration:none;font-weight:600}
.block-btn:hover{color:var(--inv-fg);opacity:.92}
.source-text{white-space:pre-wrap;color:var(--ink-3);font-size:14px}
form.input{flex:1 1 420px;min-width:0;display:flex;flex-direction:column;gap:14px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px}
form.input fieldset{border:0;margin:0;padding:0}
form.input legend{padding:0;margin-bottom:8px}
form.input .chip{font:12px var(--mono)}
textarea{width:100%;padding:12px 14px;border:1px solid var(--line-2);border-radius:6px;background:var(--subtle);font:13px/1.55 var(--mono);color:var(--ink);resize:vertical}
input[type=file]{font:14px var(--body);color:var(--ink-2)}
.tiles{display:flex;flex-wrap:wrap;gap:10px}
.tile{flex:1 1 150px;padding:14px 16px;background:var(--panel);border:1px solid var(--line);border-radius:8px}
.tile.hot{background:var(--act-tint);border-color:var(--act-border)}
.tile .n{font:800 28px var(--display);font-stretch:85%;font-variant-numeric:tabular-nums}
.tile.hot .n{color:var(--act-text)}.tile.hot .label{color:var(--act-label)}
.fix{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;padding:14px;background:var(--subtle);border-radius:6px}
.fix span:first-child{font-size:12px;color:var(--muted);display:block}.fix strong{font-weight:600}
.unres{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px;font-size:14px}
.unres li{display:flex;flex-wrap:wrap;gap:2px 12px}
.snips{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
pre{margin:6px 0 0;overflow-x:auto;padding:14px;border-radius:6px;background:var(--code-bg);color:var(--code-fg);font:12.5px/1.6 var(--mono)}
.error{padding:14px 18px;border:1px solid var(--act-border);background:var(--act-tint);color:var(--act-label);border-radius:8px}
footer.wrap{padding-bottom:40px;font-size:13px;color:var(--muted)}
@media (max-width:640px){h1{font-size:34px}h1.detail{font-size:32px}.side,.aside{max-width:none}.top .free{margin-left:0}}
`;

// Copy buttons, and filter forms that apply on change. Pages work without it.
export const JS = `document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){var i=document.getElementById(b.dataset.copy);navigator.clipboard.writeText(i.value).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1500)})})});
document.querySelectorAll('form[data-auto] input').forEach(function(i){i.addEventListener('change',function(){i.form.submit()})});`;

export const KIND_LABEL: Record<Kind, string> = {
  exploited_vuln: 'Exploited vulnerability',
  malicious_package: 'Malicious package',
  compromised_package: 'Compromised package',
  poisoned_action: 'Poisoned GitHub Action',
};
const TIER_LABEL: Record<number, string> = { 1: 'ACT NOW', 2: 'WATCH', 3: 'BULK' };

const day = (iso: string) => new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return 'never';
  const m = Math.round((now - Date.parse(iso)) / 60000);
  return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
}

/** "Ivanti Connect Secure: Ivanti Connect Secure Missing Auth..." shows as the part after the colon. */
const shortTitle = (t: string) => (t.includes(': ') ? t.slice(t.indexOf(': ') + 2) : t);
const target = (t: ThreatOut) =>
  t.affected.length
    ? t.affected.slice(0, 2).map((a) => `${a.ecosystem} / ${a.package}`).join(', ') + (t.affected.length > 2 ? ` +${t.affected.length - 2}` : '')
    : t.title.includes(': ')
      ? t.title.slice(0, t.title.indexOf(': '))
      : '';

function flags(t: ThreatOut, now = new Date()) {
  const out: { text: string; hot?: boolean }[] = [];
  if (t.kev) {
    out.push({ text: 'In CISA KEV', hot: true });
    if (t.kev.due_date) {
      const passed = Date.parse(t.kev.due_date) < now.getTime();
      out.push({ text: `Federal deadline ${day(t.kev.due_date)}${passed ? ' passed' : ''}` });
    }
    if (t.kev.ransomware) out.push({ text: 'Used by ransomware', hot: true });
  }
  if (t.epss) out.push({ text: `EPSS ${t.epss.toFixed(2)}` });
  if (t.kind === 'compromised_package') out.push({ text: 'Hijacked release', hot: true });
  if (t.affected.length && !t.affected.some((a) => a.fixed.length) && t.kind === 'exploited_vuln') out.push({ text: 'No fixed version listed' });
  return out;
}

const sourcesOf = (t: ThreatOut) => [t.kev && 'CISA KEV', t.epss && 'EPSS', t.affected.length && 'OSV'].filter(Boolean).join(', ') || 'OSV';

function layout(title: string, site: Site, active: 'feed' | 'check' | 'about' | '', body: unknown, status?: SourceStatus) {
  const dot = site.name.indexOf('.');
  const brand = dot > 0 ? html`${site.name.slice(0, dot)}<span>${site.name.slice(dot)}</span>` : site.name;
  const stale = status?.lastRun ? Date.now() - Date.parse(status.lastRun) > 40 * 60000 : true;
  return html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><meta name="description" content="Live feed of actively exploited vulnerabilities and malicious packages, with a dependency checker and MCP server.">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><meta name="theme-color" content="#101820">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="${FONTS}">
<link rel="alternate" type="application/rss+xml" title="RSS" href="/feed.xml"><link rel="alternate" type="application/atom+xml" title="Atom" href="/feed.atom">
<style>${raw(CSS)}</style></head><body>
<header class="top"><div class="wrap">
<a class="brand" href="/">${brand}</a>
<nav aria-label="Main">
<a href="/" ${active === 'feed' ? raw('aria-current="page"') : ''}>Feed</a>
<a href="/check" ${active === 'check' ? raw('aria-current="page"') : ''}>Check dependencies</a>
<a href="/api/v1/threats">API</a><a href="/#mcp">MCP</a><a href="/llms.txt">llms.txt</a>
<a href="/about" ${active === 'about' ? raw('aria-current="page"') : ''}>About</a>
</nav><span class="free">Free. No login.</span></div></header>
${status
  ? html`<div class="status"><div class="wrap" role="status">
<span><span class="dot ${stale ? 'stale' : ''}" aria-hidden="true"></span>Updated ${ago(status.lastRun)}</span>
${status.kevVersion ? html`<span>CISA KEV catalog ${status.kevVersion}</span>` : ''}
${status.epssDate ? html`<span>EPSS scores ${status.epssDate}</span>` : ''}
<span>OSV synced ${ago(status.osvAt)}</span></div></div>`
  : ''}
${body}
<footer class="wrap"><p class="small">Data: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>, <a href="https://www.first.org/epss/">FIRST EPSS</a>,
<a href="https://osv.dev">OSV</a>, OpenSSF Malicious Packages (Apache-2.0) and the GitHub Advisory Database (CC-BY 4.0).
Summaries marked AI are generated from those sources and can be wrong; check the linked sources.
<a href="/about">About and privacy</a> · <a href="${reportUrl(site)}">Report a problem</a> · <a href="${site.repo}">Source code</a></p></footer>
<script src="/app.js" defer></script></body></html>`;
}

export function feedPage(
  items: ThreatOut[],
  q: { ecosystem: string[]; kind: string[]; since: string },
  bulk: { ecosystem: string; n: number }[],
  f: Filters,
  status: SourceStatus,
  site: Site,
) {
  const windowLabel = { '24h': 'the last 24 hours', '7d': 'the last 7 days', '30d': 'the last 30 days' }[q.since] ?? 'this window';
  const bulkTotal = bulk.reduce((n, b) => n + b.n, 0);
  const mcp = `${site.url}/mcp`;
  return layout(
    'Threats being exploited right now',
    site,
    'feed',
    html`<main class="wrap">
<section class="hero"><div>
<h1>Threats being exploited right now</h1>
<p class="lede">Exploited vulnerabilities and malicious packages from CISA KEV, EPSS and OSV, merged into one feed. Checked every 10 minutes. Not every CVE: only the ones with proof of attacks or malware.</p>
</div><div>
<div class="btns"><a class="btn" href="/feed.xml">RSS</a><a class="btn" href="/feed.atom">Atom</a><a class="btn" href="/feed.json">JSON Feed</a><a class="btn" href="/api/v1/threats">JSON API</a></div>
<div id="mcp" style="display:flex;flex-direction:column;gap:4px"><label class="label" for="mcp-url">MCP server for your agent</label>
<div class="copy"><input id="mcp-url" type="text" readonly value="${mcp}"><button class="btn dark" type="button" data-copy="mcp-url">Copy</button></div></div>
</div></section>

<div class="cols">
<form class="side" method="get" action="/" data-auto aria-label="Filters">
<fieldset><legend class="label">Time window</legend><div class="seg">
${(['24h', '7d', '30d'] as const).map((w) => html`<label class="chip"><input type="radio" name="since" value="${w}" ${q.since === w ? 'checked' : ''}>${w === '24h' ? '24 h' : w.replace('d', ' d')}</label>`)}
</div></fieldset>
<fieldset><legend class="label">Signal</legend>
<label class="check"><input type="radio" name="tier" value="1" ${f.minTier === 1 ? 'checked' : ''}><span class="swatch" style="background:#C2410C" aria-hidden="true"></span>Act now only</label>
<label class="check"><input type="radio" name="tier" value="2" ${f.minTier === 2 ? 'checked' : ''}><span class="swatch" style="background:var(--watch-bg);border:1px solid var(--watch)" aria-hidden="true"></span>Act now and watch</label>
<label class="check"><input type="radio" name="tier" value="3" ${f.minTier === 3 ? 'checked' : ''}><span class="swatch" style="height:2px;background:var(--muted)" aria-hidden="true"></span>Include bulk malware</label>
</fieldset>
<fieldset><legend class="label">Type</legend>
${KINDS.map((k) => html`<label class="check"><input type="checkbox" name="kind" value="${k}" ${q.kind.includes(k) ? 'checked' : ''}>${KIND_LABEL[k]}</label>`)}
</fieldset>
<fieldset><legend class="label">Ecosystem</legend><div class="chips">
${ECOSYSTEMS.map((e) => html`<label class="chip"><input type="checkbox" name="ecosystem" value="${e}" ${q.ecosystem.includes(e) ? 'checked' : ''}>${e}</label>`)}
</div></fieldset>
<noscript><button class="btn dark" type="submit">Apply filters</button></noscript>
<a href="/" class="small">Reset filters</a>
</form>

<section class="list" aria-label="Active threats">
<div class="list-head"><h2 class="sec">${items.length}${items.length === f.limit ? '+' : ''} active threat${items.length === 1 ? '' : 's'} in ${windowLabel}</h2><span class="small">Newest signal first</span></div>
${items.length
  ? items.map(
      (t) => html`<article class="card"><div class="bar t${t.tier}">${TIER_LABEL[t.tier]}</div><div class="card-body">
<div class="meta"><span class="kind">${KIND_LABEL[t.kind]}</span><span class="mono">${t.id}</span><span>${target(t)}</span></div>
<h3><a href="/t/${encodeURIComponent(t.id)}">${shortTitle(t.title)}</a></h3>
<p>${t.summary}</p>
${flags(t).length ? html`<div class="flags">${flags(t).map((x) => html`<span class="flag ${x.hot ? 'hot' : ''}">${x.text}</span>`)}</div>` : ''}
<div class="foot"><span>Sources: <a href="/t/${encodeURIComponent(t.id)}#sources">${sourcesOf(t)}</a>${t.summary_source === 'ai' ? ' · AI summary' : ''}</span>
<span class="mono">first seen ${day(t.first_seen)} · updated ${day(t.updated_at)}</span></div>
</div></article>`,
    )
  : html`<div class="empty">Nothing matches these filters. <a href="/">Reset filters</a></div>`}
${bulkTotal && f.minTier < 3
  ? html`<div class="bulk"><span><strong>Bulk malware in ${windowLabel}:</strong> ${bulk.map((b, i) => html`${i ? (i === bulk.length - 1 ? ' and ' : ', ') : ''}${b.n} on ${b.ecosystem}`)}.
Mostly typosquats with no real users, so they stay out of the main list. Dependency checks still catch them.</span>
<a href="/?tier=3&kind=malicious_package&since=${q.since}" style="font-weight:600;white-space:nowrap">Show all ${bulkTotal}</a></div>`
  : ''}
<p class="small">Summaries are written by AI from the linked sources and regenerated when a source changes.</p>
</section></div></main>`,
    status,
  );
}

export function threatPage(t: ThreatDetail, site: Site) {
  const events: [string, string][] = [[t.first_seen, 'First seen here.']];
  if (t.kev) {
    events.push([t.kev.date_added, `Added to CISA's Known Exploited Vulnerabilities catalog${t.kev.ransomware ? ', with known ransomware use' : ''}.`]);
    if (t.kev.due_date) events.push([t.kev.due_date, 'Federal patch deadline for US agencies.']);
  }
  if (t.epss) events.push([t.updated_at, `EPSS score ${t.epss.toFixed(3)}.`]);
  if (t.updated_at !== t.first_seen) events.push([t.updated_at, 'Sources last changed.']);
  events.sort((a, b) => a[0].localeCompare(b[0]));
  const fmtWhen = (s: string) => (s.length > 10 ? s.slice(0, 16).replace('T', ' ') : s);
  return layout(
    `${t.id}: ${shortTitle(t.title)}`,
    site,
    '',
    html`<main class="wrap" style="padding-top:28px;gap:24px">
<div class="crumb"><span><a href="/">Feed</a> / <span class="mono">${t.id}</span></span><span>Also as <a href="/api/v1/threats/${encodeURIComponent(t.id)}">JSON</a></span></div>
<section style="display:flex;flex-direction:column;gap:12px">
<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px">
<span class="badge t${t.tier}">${TIER_LABEL[t.tier]}</span><span class="kind label">${KIND_LABEL[t.kind]}</span>
${t.status !== 'active' ? html`<span class="flag">${t.status}</span>` : ''}
<span class="mono" style="font-size:13px;color:var(--ink-3)">${target(t)}</span></div>
<h1 class="detail">${shortTitle(t.title)}</h1></section>

<div class="cols">
<div class="main-col">
<section class="panel" aria-label="Summary"><h2 class="act">What's happening and what to do</h2><p>${t.summary}</p></section>
<p class="small" style="margin-top:-14px">${t.summary_source === 'ai' ? 'AI summary of the sources on this page. Regenerated when a source changes.' : 'Standard summary for this kind of threat.'}</p>

${t.affected.length
  ? html`<section style="display:flex;flex-direction:column;gap:10px"><h2 class="sec">Affected versions</h2>
<div class="table-box"><table><thead><tr><th scope="col">Ecosystem</th><th scope="col">Package</th><th scope="col">Affected</th><th scope="col">Safe from</th></tr></thead><tbody>
${t.affected.map(
  (a) => html`<tr><td>${a.ecosystem}</td><td class="v">${a.package}</td><td class="v">${a.affected}</td>
<td class="v ${a.fixed.length ? 'safe' : ''}">${a.fixed.length ? a.fixed.join(', ') : t.kind === 'exploited_vuln' ? 'No fix listed' : 'None. Remove it.'}</td></tr>`,
)}</tbody></table></div>
${t.kind === 'poisoned_action' ? html`<p class="small">Tags like <code class="mono">@v4</code> can be moved, which is how these attacks work. Only a full commit SHA is safe to trust.</p>` : ''}
</section>`
  : ''}

<section style="display:flex;flex-direction:column;gap:10px"><h2 class="sec">Signals over time</h2>
<ol class="timeline">${events.map(([when, what]) => html`<li><span class="when">${fmtWhen(when)}</span><span class="what">${what}</span></li>`)}</ol></section>

<section style="display:flex;flex-direction:column;gap:10px"><h2 class="sec">Source text</h2>
<div class="panel"><p class="source-text">${t.details}</p></div></section>
</div>

<aside class="aside" aria-label="Identifiers and sources">
<div class="box"><h2 class="label">Known as</h2><div class="ids">${t.aliases.map((a) => html`<span>${a}</span>`)}</div>
<p class="small">Any of these ids opens this page, in the API and in get_threat.</p></div>
<div class="box"><h2 class="label">Signal</h2><dl class="stats">
<dt>CISA KEV</dt><dd>${t.kev ? `since ${t.kev.date_added}` : 'Not listed'}</dd>
<dt>EPSS</dt><dd>${t.epss ? t.epss.toFixed(3) : 'n/a'}</dd>
<dt>Ransomware use</dt><dd>${t.kev ? (t.kev.ransomware ? 'Known' : 'Unknown') : 'n/a'}</dd>
<dt>Severity</dt><dd>${t.severity}</dd></dl></div>
<div class="box" id="sources"><h2 class="label">Sources</h2>
${t.sources.map((s) => html`<a href="${s.url}" style="font-size:14px">${s.name === 'kev' ? 'CISA KEV' : s.name === 'epss' ? 'FIRST EPSS' : 'OSV'}: ${s.id}</a>`)}</div>
<a class="block-btn" href="/check">Check my dependencies for this</a>
<a class="btn" style="justify-content:center" href="${reportUrl(site, t.id)}">Report a problem with this entry</a>
</aside></div></main>`,
  );
}

export interface CheckView {
  manifest: string;
  format: string;
  result?: { scanned: number; matches: Match[]; unresolved: Unresolved[] };
  error?: string;
}

const FORMAT_CHOICES: [string, string][] = [
  ['', 'Detect'],
  ['package-lock', 'package-lock.json'],
  ['pnpm-lock', 'pnpm-lock.yaml'],
  ['requirements', 'requirements.txt'],
  ['poetry-lock', 'poetry.lock'],
  ['go-sum', 'go.sum'],
  ['actions', 'GitHub Actions'],
];

function fixText(m: Match): [string, string] {
  const f = m.fix;
  if (f.action === 'remove') return ['None. Remove it.', 'Rotate secrets from a different machine'];
  if (f.action === 'pin-away') return [`Any version except ${f.avoid_versions?.join(', ')}`, 'Rotate secrets on machines that installed it'];
  if (f.nearest_safe) return [f.nearest_safe, m.kind === 'exploited_vuln' ? 'Check for signs of compromise' : 'Upgrade and redeploy'];
  return [f.fixed_versions?.length ? f.fixed_versions.join(', ') : 'No fix listed', 'Check the vendor advisory'];
}

/** Copy-paste workflow; also shown in the README. Swap the lockfile name for other ecosystems. */
export const ciWorkflow = (siteUrl: string) => `# .github/workflows/compromised.yml
name: Active threat check
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a full commit SHA
      - name: Check dependencies against active threats
        run: |
          curl -sf --data-binary @package-lock.json \\
            "${siteUrl}/api/v1/check?filename=package-lock.json" > result.json
          jq '.matches[] | "\\(.name)@\\(.version): \\(.title) (\\(.threat_id))"' result.json
          jq -e '.matches | length == 0' result.json > /dev/null`;

export function checkPage(v: CheckView, site: Site) {
  const r = v.result;
  return layout(
    'Check dependencies',
    site,
    'check',
    html`<main class="wrap">
<section style="display:flex;flex-direction:column;gap:8px"><h1>Is anything in your lockfile under attack?</h1>
<p class="lede" style="max-width:64ch">Paste a lockfile or a list of GitHub Actions. Exact versions are matched against OSV, and only packages with active threats are shown: malware, compromised releases and exploited vulnerabilities. Your file is checked in memory and not stored.</p></section>
<div class="cols">
<form class="input" method="post" action="/check" enctype="multipart/form-data" aria-label="Lockfile input">
<fieldset><legend class="label">Format</legend><div class="chips">
${FORMAT_CHOICES.map(([val, label]) => html`<label class="chip"><input type="radio" name="format" value="${val}" ${v.format === val ? 'checked' : ''}>${label}</label>`)}
</div></fieldset>
<div style="display:flex;flex-direction:column;gap:6px"><label class="label" for="manifest">Lockfile contents</label>
<textarea id="manifest" name="manifest" rows="14" spellcheck="false" placeholder='{ "lockfileVersion": 3, "packages": { ... } }'>${v.manifest}</textarea>
<span class="small">Up to 2 MB. Or upload the file instead:</span>
<input type="file" name="file" aria-label="Upload a lockfile"></div>
<div><button class="btn act" type="submit">Check dependencies</button></div>
</form>

<section class="list" aria-label="Results">
${v.error ? html`<div class="error" role="alert">${v.error}</div>` : ''}
${r
  ? html`<div class="tiles">
<div class="tile"><div class="label">Packages checked</div><div class="n">${r.scanned.toLocaleString('en-US')}</div></div>
<div class="tile ${r.matches.length ? 'hot' : ''}"><div class="label">Active threats</div><div class="n">${r.matches.length}</div></div>
<div class="tile"><div class="label">Could not check</div><div class="n">${r.unresolved.length}</div></div></div>
${r.matches.length
  ? r.matches.map((m) => {
      const [safe, then] = fixText(m);
      return html`<article class="card"><div class="bar t${m.tier}">${TIER_LABEL[m.tier]}</div><div class="card-body">
<div class="meta" style="align-items:baseline"><span class="mono" style="font-size:18px;font-weight:500;color:var(--ink)">${m.name}@${m.version}</span>
<span class="kind">${KIND_LABEL[m.kind as Kind] ?? m.kind} · ${m.ecosystem}</span><a class="mono" href="${m.url}">${m.threat_id}</a></div>
<p>${m.summary}</p>
<div class="fix"><div><span>Safe version</span><strong>${safe}</strong></div><div><span>Then</span><strong>${then}</strong></div></div>
<span class="small">Think this is wrong? <a href="${reportUrl(site, m.threat_id)}">Report a false positive</a></span>
</div></article>`;
    })
  : html`<div class="empty">No active threats found in these ${r.scanned} packages.</div>`}
${r.unresolved.length
  ? html`<div class="box"><h2 class="sec" style="font-size:18px">Could not check ${r.unresolved.length} entr${r.unresolved.length === 1 ? 'y' : 'ies'}</h2>
<ul class="unres">${r.unresolved.slice(0, 50).map((u) => html`<li><span class="mono" style="font-size:13px">${u.entry}</span><span style="color:var(--ink-3)">${u.reason}</span></li>`)}</ul></div>`
  : ''}`
  : html`<div class="empty">Results appear here. Older advisories with no sign of active attacks are left out on purpose.</div>`}
<div class="snips">
<div><h2 class="label">From the command line</h2><pre>curl -sf --data-binary @package-lock.json \\
  "${site.url}/api/v1/check?filename=package-lock.json"</pre></div>
<div><h2 class="label">From an agent</h2><pre>MCP  ${site.url}/mcp
tool check_dependencies
     packages: [{ ecosystem, name, version }]</pre></div></div>
<div id="ci"><h2 class="label">In GitHub Actions: fail the build on active threats</h2><pre>${ciWorkflow(site.url)}</pre></div>
</section></div></main>`,
  );
}


export function aboutPage(site: Site) {
  const sec = (title: string, body: unknown) => html`<section class="panel" style="display:flex;flex-direction:column;gap:10px"><h2 class="sec">${title}</h2>${body}</section>`;
  return layout(
    `About ${site.name}`,
    site,
    'about',
    html`<main class="wrap" style="max-width:860px">
<section style="display:flex;flex-direction:column;gap:8px"><h1>About ${site.name}</h1>
<p class="lede">A free, no-login feed of security threats that are being exploited right now, with a dependency checker for people and AI agents.</p></section>

${sec('What counts as active', html`<p>Not every CVE. An item makes the feed only with evidence of real attacks or malware:</p>
<ul style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:4px">
<li><strong>Act now:</strong> added to CISA's Known Exploited Vulnerabilities catalog in the last 14 days, a hijacked release of a real package, or a poisoned GitHub Action.</li>
<li><strong>Watch:</strong> older KEV entries, and CVEs whose EPSS exploitation score just crossed 0.5 and that map to a package.</li>
<li><strong>Bulk:</strong> packages that were malicious from day one (typosquats). Hidden from the main list but always caught by the dependency checker.</li></ul>`)}

${sec('Privacy: what happens to your lockfile', html`<ul style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:6px">
<li>Lockfiles you paste or upload are parsed in memory and <strong>never stored or logged</strong>.</li>
<li>To match versions, the <strong>package names and versions</strong> (not the file) are sent to <a href="https://osv.dev">OSV.dev</a>, Google's open vulnerability database. Private package names in your lockfile would be part of that.</li>
<li>No accounts and no cookies. Visits are counted with Cloudflare Web Analytics, which is cookie-free and does not track you across sites.</li>
<li>Cloudflare, which hosts the site, keeps standard request logs. Fonts load from Google Fonts.</li>
<li>Checks are rate-limited per network address to keep the service fair.</li></ul>`)}

${sec('Sources and licenses', html`<ul style="margin:0;padding-left:20px;display:flex;flex-direction:column;gap:4px">
<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA Known Exploited Vulnerabilities</a></li>
<li><a href="https://www.first.org/epss/">FIRST EPSS</a> exploitation scores</li>
<li><a href="https://osv.dev">OSV</a>, including <a href="https://github.com/ossf/malicious-packages">OpenSSF Malicious Packages</a> (Apache-2.0)</li>
<li><a href="https://github.com/advisories">GitHub Advisory Database</a> (CC-BY 4.0)</li></ul>
<p>Data is refreshed every 10 minutes. ${site.name} is independent and not affiliated with any of these organizations.</p>`)}

${sec('AI summaries', html`<p>Summaries marked AI are written by Claude (Anthropic) from the public advisory text only, and regenerated when a source changes. Only public advisory data is sent to the model, never anything you paste. They can be wrong, so each one links to its sources.</p>`)}

${sec('Who runs this', html`<p>${site.name} is an independent side project, provided as is with no warranty. Use it as an extra early-warning signal alongside your own security tooling, not instead of it. The <a href="${site.repo}">source code is public</a>.</p>`)}

${sec('Found a mistake?', html`<p>False positives and missing threats matter on a security tool. Please <a href="${reportUrl(site)}">report it on GitHub</a>; every threat page and check result also has a report link.</p>`)}
</main>`,
  );
}
