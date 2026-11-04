import semver from 'semver';
import type { Adapter, Env, OsvRange, Severity, SourceRecord } from '../types';
import { kevDates } from './kev';

const CORE = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';
const RSS = 'https://nodejs.org/en/feed/vulnerability.xml';
const DIST = 'https://nodejs.org/dist/index.json';
const BLOG_MD = 'https://raw.githubusercontent.com/nodejs/nodejs.org/main/apps/site/pages/en/blog/vulnerability/';
const WINDOW_DAYS = 30;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export interface CoreEntry {
  cve?: string[];
  vulnerable?: string;
  patched?: string;
  ref?: string;
  description?: string;
  overview?: string;
  severity?: string;
}

export interface Release {
  title: string;
  link: string;
  slug: string;
  published: string;
}

interface NodeCursor {
  /** Newest release per major line, from dist/index.json. */
  latest?: Record<string, string>;
  v?: number;
}

const sev = (s?: string): Severity => (SEVERITIES as string[]).includes(s?.toLowerCase() ?? '') ? (s!.toLowerCase() as Severity) : 'unknown';
const cdata = (s: string) => s.replace(/^<!\[CDATA\[([\s\S]*)\]\]>$/, '$1').trim();

export function parseReleases(xml: string): Release[] {
  return [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].flatMap(([, item]) => {
    const tag = (n: string) => cdata(item.match(new RegExp(`<${n}>([\\s\\S]*?)</${n}>`))?.[1] ?? '');
    const title = tag('title');
    const link = tag('link');
    const published = Date.parse(tag('pubDate'));
    const slug = link.match(/\/vulnerability\/([\w-]+)$/)?.[1];
    if (!/security releases/i.test(title) || !slug || Number.isNaN(published)) return [];
    return [{ title, link, slug, published: new Date(published).toISOString() }];
  });
}

/** Newest stable version per major, e.g. { "22": "22.23.4" }. */
export function latestPerLine(dist: { version: string }[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const { version } of dist) {
    const v = semver.parse(version);
    if (!v || v.prerelease.length) continue;
    if (!out[v.major] || semver.gt(v, out[v.major])) out[v.major] = v.version;
  }
  return out;
}

/** One OSV range per release line: patched lines get a fix, vulnerable lines without one stay affected through their latest release. */
export function nodeRanges(vulnerable: string, patched: string, latest: Record<string, string>): OsvRange[] {
  const majorOf = (part: string) => {
    if (!part || part === '*') return undefined;
    try {
      return semver.minVersion(part)?.major;
    } catch {
      return undefined;
    }
  };
  const ranges = new Map<number, OsvRange>();
  for (const part of patched.split('||').map((p) => p.trim())) {
    const major = majorOf(part);
    if (major === undefined) continue;
    const fixed = semver.minVersion(part)!.version;
    ranges.set(major, { type: 'SEMVER', events: [{ introduced: `${major}.0.0` }, { fixed }] });
  }
  for (const part of vulnerable.split('||').map((p) => p.trim())) {
    const major = majorOf(part);
    if (major === undefined || ranges.has(major) || !latest[major]) continue;
    ranges.set(major, { type: 'SEMVER', events: [{ introduced: `${major}.0.0` }, { last_affected: latest[major] }] });
  }
  return [...ranges.values()].sort((a, b) => semver.compare(a.events[0].introduced, b.events[0].introduced));
}

const NODE_URL = 'https://nodejs.org/en/blog/vulnerability';
const cvesOf = (e: CoreEntry) => (e.cve ?? []).filter((c) => /^CVE-\d{4}-\d+$/.test(c));
const rank = (s: Severity) => (s === 'unknown' ? 9 : SEVERITIES.indexOf(s));

/** Union of every entry's ranges: per line, the highest fix (a release fixes all its CVEs at once). */
export function combinedRanges(entries: CoreEntry[], latest: Record<string, string>): OsvRange[] {
  const byMajor = new Map<string, OsvRange>();
  for (const e of entries)
    for (const r of nodeRanges(e.vulnerable ?? '', e.patched ?? '', latest)) {
      const cur = byMajor.get(r.events[0].introduced);
      const fixed = r.events[1].fixed;
      const curFixed = cur?.events[1].fixed;
      if (!cur || (fixed && (!curFixed || semver.gt(fixed, curFixed)))) byMajor.set(r.events[0].introduced, r);
    }
  return [...byMajor.values()].sort((a, b) => semver.compare(a.events[0].introduced, b.events[0].introduced));
}

/** A KEV-listed runtime CVE stands on its own so the existing tier rules apply. */
export function exploitedRecord(key: string, e: CoreEntry, latest: Record<string, string>, kevAdded: string): SourceRecord {
  const cves = cvesOf(e);
  return {
    source: 'nodejs',
    sourceId: cves[0] ?? `nodejs-core-${key}`,
    aliases: cves,
    kind: 'exploited_vuln',
    title: `Node.js: ${e.description ?? cves[0]}`,
    details: e.overview ?? e.description ?? '',
    severity: sev(e.severity),
    affected: [{ ecosystem: 'Node.js', package: 'node', ranges: nodeRanges(e.vulnerable ?? '', e.patched ?? '', latest), versions: [] }],
    url: e.ref ?? NODE_URL,
    published: kevAdded,
    kev: { dateAdded: kevAdded, dueDate: '', ransomware: false, requiredAction: 'Upgrade Node.js to a patched release.' },
  };
}

/** Lines and severity from the pre-alert post, e.g. "The highest severity issue fixed in the 22.x release line is HIGH." */
export function parsePrealert(md: string): { lines: string[]; severity: Severity } {
  const lines = [...md.matchAll(/in the (\d+)\.x release line is (\w+)/gi)].map((m) => `${m[1]}.x`);
  const overall = sev(md.match(/highest severity issue fixed in this release is (\w+)/i)?.[1]);
  return { lines: [...new Set(lines)], severity: overall };
}

/**
 * One item per security release, updated in place: a pre-alert until the CVEs are out, then the fixed versions.
 * KEV-listed CVEs are left out of `entries` (they get their own exploited item) but still count in the text.
 */
export function releaseRecord(r: Release, pre: { lines: string[]; severity: Severity }, entries: CoreEntry[], exploited: string[], latest: Record<string, string>): SourceRecord {
  const when = r.title.replace(/\s*Security Releases\s*$/i, '');
  const base = { source: 'nodejs', sourceId: `nodejs-${r.slug}`, kind: 'security_release' as const, url: r.link, published: r.published };
  if (!entries.length && !exploited.length) {
    const lines = pre.lines.length ? pre.lines.join(', ') : 'supported';
    const sevText = pre.severity === 'unknown' ? '' : ` The highest severity is ${pre.severity.toUpperCase()}.`;
    return {
      ...base,
      aliases: [base.sourceId],
      title: `Node.js: Security releases for ${lines} on ${when}`,
      details: `The Node.js project will release fixes for the ${lines} release lines on or shortly after ${when}.${sevText} End-of-life lines are always affected. Fixed versions appear here on release day.`,
      severity: pre.severity,
      affected: [],
    };
  }
  const ranges = combinedRanges(entries, latest);
  const fixed = ranges.map((x) => x.events[1].fixed).filter(Boolean);
  const severity = entries.map((e) => sev(e.severity)).reduce<Severity>((a, b) => (rank(b) < rank(a) ? b : a), 'unknown');
  const n = entries.length + exploited.length;
  const kevText = exploited.length ? ` ${exploited.join(', ')} ${exploited.length === 1 ? 'is' : 'are'} known to be exploited and listed separately.` : '';
  const list = entries.map((e) => `${cvesOf(e).join(', ') || 'No CVE'} (${sev(e.severity)}): ${e.description ?? ''}`);
  return {
    ...base,
    aliases: [base.sourceId, ...entries.flatMap(cvesOf)],
    title: `Node.js: Security releases of ${when}, ${n} fix${n === 1 ? '' : 'es'}`,
    details: `Node.js released ${fixed.join(', ') || 'patched versions'} with ${n} security fix${n === 1 ? '' : 'es'}${severity === 'unknown' ? '' : `, highest severity ${severity.toUpperCase()}`}.${kevText} Upgrade to the fixed release for your line.\n\n${list.join('\n')}`,
    severity,
    affected: entries.length ? [{ ecosystem: 'Node.js', package: 'node', ranges, versions: [] }] : [],
  };
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`nodejs ${url}: ${res.status}`);
  return res.json();
}

// ponytail: one-time removal of the per-CVE items from the first version; delete once every deployment has run it.
async function dropPerCveItems(env: Env) {
  const only = "SELECT threat_id FROM source_records GROUP BY threat_id HAVING SUM(source <> 'nodejs') = 0";
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM affected WHERE threat_id IN (${only})`),
    env.DB.prepare(`DELETE FROM aliases WHERE threat_id IN (${only})`),
    env.DB.prepare(`DELETE FROM threats WHERE id IN (${only})`),
    env.DB.prepare("DELETE FROM affected WHERE ecosystem = 'Node.js'"),
    env.DB.prepare("DELETE FROM source_records WHERE source = 'nodejs'"),
  ]);
}

/** One item per recent Node.js security release, plus a separate item for each KEV-listed runtime CVE. */
export const nodejs: Adapter = {
  name: 'nodejs',
  async run(env: Env, cursor, now) {
    const prev: NodeCursor = cursor ? JSON.parse(cursor) : {};
    if (cursor && prev.v !== 2) await dropPerCveItems(env);
    const [core, xml, dist] = await Promise.all([
      getJson<Record<string, CoreEntry>>(CORE),
      fetch(RSS).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`nodejs ${RSS}: ${r.status}`)))),
      getJson<{ version: string }[]>(DIST),
    ]);
    const latest = latestPerLine(dist);
    const since = new Date(now.getTime() - WINDOW_DAYS * 864e5).toISOString();
    const recent = parseReleases(xml).filter((r) => r.published >= since);
    const kev = await kevDates(env);

    const recentRefs = new Set(recent.map((r) => r.link));
    const records: SourceRecord[] = [];
    const byRef = new Map<string, { entries: CoreEntry[]; exploited: string[] }>();
    for (const [key, e] of Object.entries(core)) {
      const g = byRef.get(e.ref ?? '') ?? { entries: [], exploited: [] };
      byRef.set(e.ref ?? '', g);
      const kevCve = cvesOf(e).find((c) => kev[c]);
      if (!kevCve) g.entries.push(e);
      // Old KEV entries are not news; newer release ranges still flag those versions.
      else if (recentRefs.has(e.ref ?? '') || kev[kevCve] >= since.slice(0, 10)) {
        g.exploited.push(kevCve);
        records.push(exploitedRecord(key, e, latest, kev[kevCve]));
      }
    }
    for (const r of recent) {
      const g = byRef.get(r.link) ?? { entries: [], exploited: [] };
      const pre = g.entries.length || g.exploited.length ? { lines: [], severity: 'unknown' as Severity } : parsePrealert(await fetch(`${BLOG_MD}${r.slug}.md`).then((x) => (x.ok ? x.text() : '')));
      records.push(releaseRecord(r, pre, g.entries, g.exploited, latest));
    }
    return { records, cursor: JSON.stringify({ v: 2, latest } satisfies NodeCursor) };
  },
};

export async function latestNodeReleases(env: Env): Promise<Record<string, string>> {
  const row = await env.DB.prepare("SELECT cursor FROM cursors WHERE source = 'nodejs'").first<{ cursor: string }>();
  return row ? ((JSON.parse(row.cursor) as NodeCursor).latest ?? {}) : {};
}
