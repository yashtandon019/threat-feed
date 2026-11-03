import { html, raw } from 'hono/html';
import type { Filters, ThreatOut } from './db';
import type { getThreat } from './db';
import { ECOSYSTEMS, KINDS } from './types';

const CSS = `
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--line:#e7e5e4;--card:#fff;--t1:#b91c1c;--t2:#c2410c;--t3:#78716c}
@media (prefers-color-scheme:dark){:root{--bg:#141210;--fg:#f5f5f4;--muted:#a8a29e;--line:#2e2a27;--card:#1c1917;--t1:#f87171;--t2:#fb923c;--t3:#a8a29e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px 64px}a{color:inherit}h1{font-size:26px;margin:0 0 4px}
.muted{color:var(--muted)}form{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0}select,button{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
article{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:10px 0}
article h2{font-size:16px;margin:0 0 6px}article p{margin:6px 0}.tag{font:12px ui-monospace,monospace;padding:1px 6px;border-radius:4px;border:1px solid var(--line);margin-right:4px;white-space:nowrap}
.t1{color:var(--t1);border-color:var(--t1)}.t2{color:var(--t2);border-color:var(--t2)}.t3{color:var(--t3)}
code{font:13px ui-monospace,monospace;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}
footer{margin-top:40px;font-size:13px}`;

function page(title: string, body: unknown) {
  return html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><link rel="alternate" type="application/rss+xml" href="/feed.xml"><style>${raw(CSS)}</style></head>
<body><main>${body}
<footer class="muted">Data: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>,
<a href="https://www.first.org/epss/">FIRST EPSS</a>, <a href="https://osv.dev">OSV</a> (including OpenSSF Malicious Packages and the GitHub Advisory Database, CC-BY 4.0).
Summaries marked AI are generated from those sources and can be wrong; check the linked sources.
· <a href="/feed.xml">RSS</a> · <a href="/feed.atom">Atom</a> · <a href="/feed.json">JSON Feed</a> · <a href="/api/v1/threats">API</a> · <a href="/llms.txt">llms.txt</a> · MCP: <code>/mcp</code></footer>
</main></body></html>`;
}

function tags(t: ThreatOut) {
  return html`<span class="tag t${t.tier}">tier ${t.tier}</span><span class="tag">${t.kind.replace('_', ' ')}</span>${t.kev
    ? html`<span class="tag t1">CISA KEV</span>`
    : ''}${t.epss ? html`<span class="tag">EPSS ${t.epss.toFixed(2)}</span>` : ''}`;
}

function select(name: string, options: [string, string][], current: string) {
  return html`<select name="${name}" aria-label="${name}">${options.map(
    ([v, label]) => html`<option value="${v}" ${v === current ? 'selected' : ''}>${label}</option>`,
  )}</select>`;
}

export function feedPage(items: ThreatOut[], q: Record<string, string>, bulk: { ecosystem: string; n: number }[], f: Filters) {
  return page(
    'Active security threats',
    html`<h1>Active security threats</h1>
<p class="muted">Exploited vulnerabilities and malicious or hijacked packages that are happening now, not every CVE. Updated every 10 minutes.</p>
<form method="get">
${select('ecosystem', [['', 'All ecosystems'], ...ECOSYSTEMS.map((e): [string, string] => [e, e])], q.ecosystem ?? '')}
${select('kind', [['', 'All types'], ...KINDS.map((k): [string, string] => [k, k.replace('_', ' ')])], q.kind ?? '')}
${select('tier', [['1', 'Tier 1 only'], ['2', 'Tier 1-2'], ['3', 'All tiers']], String(f.minTier))}
${select('since', [['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']], q.since ?? '7d')}
<button>Filter</button></form>
${bulk.length && f.minTier < 3
  ? html`<p class="muted">Also new in this window: ${bulk.map((b, i) => html`${i ? ', ' : ''}${b.n} malicious ${b.ecosystem} packages`)}
(throwaway typosquats, <a href="?tier=3&kind=malicious_package&since=${q.since ?? '7d'}">list them</a>).</p>`
  : ''}
${items.length ? items.map(
  (t) => html`<article><h2><a href="/t/${encodeURIComponent(t.id)}">${t.title}</a></h2><div>${tags(t)}</div>
<p>${t.summary}</p>
<p class="muted">${t.affected.slice(0, 4).map((a) => html`<code>${a.ecosystem}/${a.package}</code> `)}${t.affected.length > 4
    ? `+${t.affected.length - 4} more`
    : ''} · ${t.id} · updated ${t.updated_at.slice(0, 16).replace('T', ' ')} UTC</p></article>`,
) : html`<p>Nothing matches these filters.</p>`}`,
  );
}

export function threatPage(t: NonNullable<Awaited<ReturnType<typeof getThreat>>>) {
  return page(
    `${t.id}: ${t.title}`,
    html`<p><a href="/">← All threats</a></p><h1>${t.title}</h1><div>${tags(t)}${t.status !== 'active'
      ? html`<span class="tag">${t.status}</span>`
      : ''}</div>
<p>${t.summary} <span class="muted">(${t.summary_source === 'ai' ? 'AI summary' : 'template summary'})</span></p>
${t.kev ? html`<p>Added to CISA KEV ${t.kev.date_added}, federal due date ${t.kev.due_date}${t.kev.ransomware ? ', used in ransomware campaigns' : ''}.</p>` : ''}
${t.affected.length
  ? html`<h2>Affected packages</h2><table><tr><th>Package</th><th>Affected</th><th>Fixed in</th></tr>${t.affected.map(
      (a) => html`<tr><td><code>${a.ecosystem}/${a.package}</code></td><td><code>${a.affected}</code></td><td><code>${a.fixed.join(', ') || 'none'}</code></td></tr>`,
    )}</table>`
  : ''}
<h2>Sources</h2><ul>${t.sources.map((s) => html`<li><a href="${s.url}">${s.name}: ${s.id}</a></li>`)}</ul>
<p class="muted">Aliases: ${t.aliases.join(', ')} · first seen ${t.first_seen} · updated ${t.updated_at}</p>
<h2>Source text</h2><p style="white-space:pre-wrap">${t.details}</p>`,
  );
}
