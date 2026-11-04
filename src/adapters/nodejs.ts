import semver from 'semver';
import type { Adapter, Env, OsvRange, Severity, SourceRecord } from '../types';
import { knownExploitedCves } from './kev';

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
  /** Pre-alerts already emitted, so they can be withdrawn once CVEs are out. */
  prealerts?: string[];
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

export function cveRecord(key: string, e: CoreEntry, latest: Record<string, string>, published: string): SourceRecord {
  const cves = (e.cve ?? []).filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  return {
    source: 'nodejs',
    sourceId: cves[0] ?? `nodejs-core-${key}`,
    aliases: cves.length ? cves : [`nodejs-core-${key}`],
    kind: 'runtime_vuln',
    title: `Node.js: ${e.description ?? cves[0] ?? 'security fix'}`,
    details: e.overview ?? e.description ?? '',
    severity: sev(e.severity),
    affected: [{ ecosystem: 'Node.js', package: 'node', ranges: nodeRanges(e.vulnerable ?? '', e.patched ?? '', latest), versions: [] }],
    url: e.ref ?? 'https://nodejs.org/en/blog/vulnerability',
    published,
  };
}

/** Lines and severity from the pre-alert post, e.g. "The highest severity issue fixed in the 22.x release line is HIGH." */
export function parsePrealert(md: string): { lines: string[]; severity: Severity } {
  const lines = [...md.matchAll(/in the (\d+)\.x release line is (\w+)/gi)].map((m) => ({ line: `${m[1]}.x`, sev: sev(m[2]) }));
  const overall = sev(md.match(/highest severity issue fixed in this release is (\w+)/i)?.[1]);
  return { lines: [...new Set(lines.map((l) => l.line))], severity: overall };
}

export function prealertRecord(r: Release, info: { lines: string[]; severity: Severity }, withdrawn: boolean): SourceRecord {
  const when = r.title.replace(/\s*Security Releases\s*$/i, '');
  const lines = info.lines.length ? info.lines.join(', ') : 'supported';
  const sevText = info.severity === 'unknown' ? '' : ` The highest severity is ${info.severity.toUpperCase()}.`;
  return {
    source: 'nodejs',
    sourceId: `nodejs-${r.slug}`,
    aliases: [`nodejs-${r.slug}`],
    kind: 'security_release',
    title: `Node.js: Security releases for ${lines} on ${when}`,
    details: `The Node.js project will release fixes for the ${lines} release lines on or shortly after ${when}.${sevText} End-of-life lines are always affected. CVE details and fixed versions are published on release day.`,
    severity: info.severity,
    affected: [],
    url: r.link,
    published: r.published,
    withdrawn,
  };
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`nodejs ${url}: ${res.status}`);
  return res.json();
}

/** Recent CVEs (plus any in KEV) from the security WG index, and pre-alerts for releases whose CVEs are not out yet. */
export const nodejs: Adapter = {
  name: 'nodejs',
  async run(env: Env, cursor, now) {
    const prev: NodeCursor = cursor ? JSON.parse(cursor) : {};
    const [core, xml, dist] = await Promise.all([
      getJson<Record<string, CoreEntry>>(CORE),
      fetch(RSS).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`nodejs ${RSS}: ${r.status}`)))),
      getJson<{ version: string }[]>(DIST),
    ]);
    const latest = latestPerLine(dist);
    const since = new Date(now.getTime() - WINDOW_DAYS * 864e5).toISOString();
    const recent = parseReleases(xml).filter((r) => r.published >= since);
    const published = new Map(recent.map((r) => [r.link, r.published]));
    const kev = await knownExploitedCves(env);

    const records: SourceRecord[] = [];
    const released = new Set<string>();
    for (const [key, e] of Object.entries(core)) {
      if (e.ref) released.add(e.ref);
      const inKev = (e.cve ?? []).some((c) => kev.has(c));
      if (!(e.ref && published.has(e.ref)) && !inKev) continue;
      records.push(cveRecord(key, e, latest, published.get(e.ref ?? '') ?? now.toISOString()));
    }

    const prealerts: string[] = [];
    for (const r of recent) {
      const out = released.has(r.link);
      if (out && !prev.prealerts?.includes(r.slug)) continue;
      if (!out) prealerts.push(r.slug);
      const md = await fetch(`${BLOG_MD}${r.slug}.md`).then((x) => (x.ok ? x.text() : ''));
      records.push(prealertRecord(r, parsePrealert(md), out));
    }
    return { records, cursor: JSON.stringify({ latest, prealerts } satisfies NodeCursor) };
  },
};

export async function latestNodeReleases(env: Env): Promise<Record<string, string>> {
  const row = await env.DB.prepare("SELECT cursor FROM cursors WHERE source = 'nodejs'").first<{ cursor: string }>();
  return row ? ((JSON.parse(row.cursor) as NodeCursor).latest ?? {}) : {};
}
