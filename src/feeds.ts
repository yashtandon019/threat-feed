import type { ThreatOut } from './db';

const TITLE = 'Active security threats';
const DESC = 'Exploited vulnerabilities and malicious or compromised packages, merged from CISA KEV, EPSS and OSV.';

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!);

function line(t: ThreatOut) {
  const pkgs = t.affected.map((a) => `${a.ecosystem}/${a.package}`).join(', ');
  return `[Tier ${t.tier}] ${t.title}${pkgs ? ` (${pkgs})` : ''}`;
}

export function rss(items: ThreatOut[], selfUrl: string, site: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>
<title>${TITLE}</title><link>${esc(site)}</link><description>${DESC}</description>
<atom:link href="${esc(selfUrl)}" rel="self" type="application/rss+xml"/>
${items
  .map(
    (t) => `<item><title>${esc(line(t))}</title><link>${esc(t.url)}</link><guid isPermaLink="false">${esc(t.id)}@${esc(t.updated_at)}</guid>
<pubDate>${new Date(t.updated_at).toUTCString()}</pubDate><category>${t.kind}</category><description>${esc(t.summary)}</description></item>`,
  )
  .join('\n')}
</channel></rss>`;
}

export function atom(items: ThreatOut[], selfUrl: string, site: string): string {
  const updated = items[0]?.updated_at ?? new Date().toISOString();
  return `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>${TITLE}</title><subtitle>${DESC}</subtitle><id>${esc(site)}/</id><updated>${updated}</updated>
<link href="${esc(site)}"/><link rel="self" href="${esc(selfUrl)}"/>
${items
  .map(
    (t) => `<entry><title>${esc(line(t))}</title><id>${esc(t.url)}</id><link href="${esc(t.url)}"/>
<published>${t.first_seen}</published><updated>${t.updated_at}</updated><category term="${t.kind}"/>
<summary>${esc(t.summary)}</summary><author><name>threat-feed</name></author></entry>`,
  )
  .join('\n')}
</feed>`;
}

export function jsonFeed(items: ThreatOut[], selfUrl: string, site: string) {
  return {
    version: 'https://jsonfeed.org/version/1.1',
    title: TITLE,
    description: DESC,
    home_page_url: site,
    feed_url: selfUrl,
    items: items.map((t) => ({
      id: t.id,
      url: t.url,
      title: line(t),
      content_text: t.summary,
      date_published: t.first_seen,
      date_modified: t.updated_at,
      tags: [t.kind, `tier-${t.tier}`, ...t.affected.map((a) => a.ecosystem)],
      _threat: t,
    })),
  };
}
