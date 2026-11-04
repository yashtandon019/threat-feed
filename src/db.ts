import { KINDS, normalizeEcosystem, type Env, type Kind, type OsvRange } from './types';

export interface Filters {
  ecosystems: string[];
  kinds: Kind[];
  minTier: number;
  since: string;
  limit: number;
}

const WINDOWS: Record<string, number> = { '24h': 1, '7d': 7, '30d': 30 };

function list(v: string | string[] | undefined): string[] {
  return (Array.isArray(v) ? v : (v ?? '').split(',')).map((s) => s.trim()).filter(Boolean);
}

/** One parser for web, feeds, API and MCP so every surface filters the same way. */
export function parseFilters(
  q: { ecosystem?: string | string[]; kind?: string | string[]; tier?: string | number; since?: string; limit?: string | number },
  now = new Date(),
): Filters {
  const since = q.since ?? '7d';
  const parsed = Date.parse(since);
  const sinceIso = WINDOWS[since] || Number.isNaN(parsed)
    ? new Date(now.getTime() - (WINDOWS[since] ?? 7) * 864e5).toISOString()
    : new Date(parsed).toISOString();
  return {
    ecosystems: list(q.ecosystem).map(normalizeEcosystem).filter((e): e is string => !!e),
    kinds: list(q.kind).filter((k): k is Kind => (KINDS as readonly string[]).includes(k)),
    minTier: Math.min(3, Math.max(1, Number(q.tier ?? 2) || 2)),
    since: sinceIso,
    limit: Math.min(100, Math.max(1, Number(q.limit ?? 50) || 50)),
  };
}

export interface ThreatRow {
  id: string;
  kind: Kind;
  tier: number;
  title: string;
  severity: string;
  summary: string;
  summary_model: string;
  details: string;
  epss: number | null;
  kev_added: string | null;
  kev_due: string | null;
  ransomware: number;
  status: string;
  first_seen: string;
  updated_at: string;
  last_signal_at: string;
  refs_json?: string;
}

export interface AffectedOut {
  ecosystem: string;
  package: string;
  affected: string;
  fixed: string[];
}

/** The affected set as a union: one interval per introduced..fixed/last_affected pair, plus any listed versions. */
export function describeRanges(ranges: OsvRange[], versions: string[]): string {
  const intervals: string[] = [];
  for (const r of ranges) {
    let from: string | undefined;
    for (const e of r.events) {
      if (e.introduced !== undefined) from = e.introduced;
      const end = e.fixed !== undefined ? `< ${e.fixed}` : e.last_affected !== undefined ? `<= ${e.last_affected}` : undefined;
      if (end !== undefined) {
        intervals.push(!from || from === '0' ? end : `>= ${from}, ${end}`);
        from = undefined;
      }
    }
    if (from !== undefined) intervals.push(from === '0' ? 'all versions' : `>= ${from}`);
  }
  const parts = [...intervals, ...(versions.length ? [versions.join(', ')] : [])];
  return parts.join(' or ') || 'unknown';
}

function toAffectedOut(r: { ecosystem: string; package: string; ranges_json: string; versions_json: string }): AffectedOut {
  const ranges = JSON.parse(r.ranges_json) as OsvRange[];
  return {
    ecosystem: r.ecosystem,
    package: r.package,
    affected: describeRanges(ranges, JSON.parse(r.versions_json)),
    fixed: ranges.flatMap((x) => x.events.map((e) => e.fixed).filter((f): f is string => !!f)),
  };
}

export type ThreatOut = ReturnType<typeof toOut>;

function toOut(t: ThreatRow, affected: AffectedOut[], siteUrl: string) {
  return {
    id: t.id,
    url: `${siteUrl}/t/${encodeURIComponent(t.id)}`,
    kind: t.kind,
    tier: t.tier,
    severity: t.severity,
    title: t.title,
    summary: t.summary,
    summary_source: t.summary_model === 'template' ? 'template' : 'ai',
    affected,
    epss: t.epss,
    kev: t.kev_added ? { date_added: t.kev_added, due_date: t.kev_due, ransomware: !!t.ransomware } : null,
    first_seen: t.first_seen,
    updated_at: t.updated_at,
    /** Set when this item stands for several threats from one campaign; each id still resolves on its own. */
    campaign: null as null | { members: { id: string; url: string; affected: AffectedOut[] }[] },
  };
}

async function affectedFor(env: Env, ids: string[]) {
  const map = new Map<string, AffectedOut[]>();
  const rows = [];
  for (let i = 0; i < ids.length; i += 90) {
    const chunk = ids.slice(i, i + 90); // D1 allows 100 bound parameters per statement
    rows.push(
      ...(
        await env.DB.prepare(`SELECT * FROM affected WHERE threat_id IN (${chunk.map(() => '?').join(',')})`)
          .bind(...chunk)
          .all<{ threat_id: string; ecosystem: string; package: string; ranges_json: string; versions_json: string }>()
      ).results,
    );
  }
  for (const r of rows) map.set(r.threat_id, [...(map.get(r.threat_id) ?? []), toAffectedOut(r)]);
  return map;
}

export async function listThreats(env: Env, f: Filters): Promise<ThreatOut[]> {
  // Heads-up (tier 4) shows with every filter except "act now only".
  const where = [`t.status = 'active'`, '(t.tier <= ? OR (t.tier = 4 AND ? >= 2))', 't.last_signal_at >= ?'];
  const binds: unknown[] = [f.minTier, f.minTier, f.since];
  if (f.kinds.length) {
    where.push(`t.kind IN (${f.kinds.map(() => '?').join(',')})`);
    binds.push(...f.kinds);
  }
  if (f.ecosystems.length) {
    where.push(`EXISTS (SELECT 1 FROM affected a WHERE a.threat_id = t.id AND a.ecosystem IN (${f.ecosystems.map(() => '?').join(',')}))`);
    binds.push(...f.ecosystems);
  }
  // ponytail: over-fetch so a wave collapses instead of eating the limit; a wave larger than this splits.
  const rows = (
    await env.DB.prepare(`SELECT t.* FROM threats t WHERE ${where.join(' AND ')} ORDER BY t.last_signal_at DESC LIMIT ?`)
      .bind(...binds, f.limit * 5)
      .all<ThreatRow>()
  ).results;
  const aff = await affectedFor(env, rows.map((r) => r.id));
  return groupCampaigns(rows.map((r) => ({ out: toOut(r, aff.get(r.id) ?? [], env.SITE_URL), refs: JSON.parse(r.refs_json ?? '[]') as string[] }))).slice(0, f.limit);
}

const CAMPAIGN_KINDS: Kind[] = ['compromised_package', 'malicious_package'];
export const CAMPAIGN_WINDOW_HOURS = 72;

/** Package malware that shares a third-party write-up and was first seen within the window becomes one item. Display only. */
export function groupCampaigns(items: { out: ThreatOut; refs: string[] }[]): ThreatOut[] {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const byRef = new Map<string, number[]>();
  items.forEach((it, i) => {
    if (CAMPAIGN_KINDS.includes(it.out.kind)) for (const r of new Set(it.refs)) byRef.set(r, [...(byRef.get(r) ?? []), i]);
  });
  const near = (a: number, b: number) =>
    Math.abs(Date.parse(items[a].out.first_seen) - Date.parse(items[b].out.first_seen)) <= CAMPAIGN_WINDOW_HOURS * 3600e3;
  for (const idx of byRef.values()) {
    idx.sort((a, b) => items[a].out.first_seen.localeCompare(items[b].out.first_seen));
    for (let k = 1; k < idx.length; k++) if (near(idx[k - 1], idx[k])) parent[find(idx[k])] = find(idx[k - 1]);
  }

  const groups = new Map<number, ThreatOut[]>();
  items.forEach((it, i) => groups.set(find(i), [...(groups.get(find(i)) ?? []), it.out]));
  const out: ThreatOut[] = [];
  items.forEach((it, i) => {
    const g = groups.get(find(i))!;
    if (g[0] !== it.out) return;
    if (g.length === 1) return out.push(it.out);
    const lead = g.reduce((a, b) => (b.tier < a.tier ? b : a));
    const pkgs = (ts: ThreatOut[]) => new Set(ts.flatMap((t) => t.affected.map((a) => `${a.ecosystem}/${a.package}`))).size;
    const n = pkgs(g);
    const hijacks = pkgs(g.filter((t) => t.kind === 'compromised_package'));
    out.push({
      ...lead,
      // n = 1: one package listed under two not-yet-linked advisories, so keep its own title.
      title: n === 1 ? lead.title : hijacks
        ? `${hijacks} hijacked package${hijacks === 1 ? '' : 's'} in one campaign` + (n > hijacks ? ` (+${n - hijacks} malicious)` : '')
        : `${n} malicious package${n === 1 ? '' : 's'} in one campaign`,
      affected: g.flatMap((t) => t.affected),
      first_seen: g.map((t) => t.first_seen).sort()[0],
      updated_at: g.map((t) => t.updated_at).sort().at(-1)!,
      campaign: { members: g.map((t) => ({ id: t.id, url: t.url, affected: t.affected })) },
    });
  });
  return out;
}

/** Accepts any alias (CVE, GHSA, MAL, OSV id). */
export async function getThreat(env: Env, idOrAlias: string) {
  const t = await env.DB.prepare('SELECT t.* FROM aliases a JOIN threats t ON t.id = a.threat_id WHERE a.alias = ?')
    .bind(idOrAlias)
    .first<ThreatRow>();
  if (!t) return null;
  const [aff, aliases, sources] = await Promise.all([
    affectedFor(env, [t.id]),
    env.DB.prepare('SELECT alias FROM aliases WHERE threat_id = ? ORDER BY alias').bind(t.id).all<{ alias: string }>(),
    env.DB.prepare('SELECT source, source_id, url FROM source_records WHERE threat_id = ? ORDER BY source').bind(t.id).all<{ source: string; source_id: string; url: string }>(),
  ]);
  return {
    ...toOut(t, aff.get(t.id) ?? [], env.SITE_URL),
    status: t.status,
    details: t.details,
    aliases: aliases.results.map((a) => a.alias),
    sources: sources.results.map((s) => ({ name: s.source, id: s.source_id, url: s.url })),
  };
}

export interface SourceStatus {
  lastRun: string | null;
  sources: Record<string, string | null>;
  kevVersion: string | null;
  epssDate: string | null;
  osvAt: string | null;
}

/** Every adapter in ingest.ts ADAPTERS; listed here to avoid an import cycle. */
export const SOURCES = ['kev', 'epss', 'ghsa', 'osv_mal', 'nodejs'] as const;

/** Freshness for the status strip, read from the adapter cursors. */
export async function sourceStatus(env: Env): Promise<SourceStatus> {
  const rows = (await env.DB.prepare('SELECT source, cursor, updated_at FROM cursors').all<{ source: string; cursor: string; updated_at: string }>()).results;
  const by = Object.fromEntries(rows.map((r) => [r.source, r]));
  const json = (s: string | undefined) => (s ? (JSON.parse(s) as Record<string, unknown>) : {});
  const runs = SOURCES.map((s) => by[s]?.updated_at);
  return {
    // The oldest source decides freshness: one healthy adapter must not hide a failing one.
    lastRun: runs.every(Boolean) ? (runs as string[]).sort()[0] : null,
    sources: Object.fromEntries(SOURCES.map((s, i) => [s, runs[i] ?? null])),
    kevVersion: (json(by.kev?.cursor).version as string) ?? null,
    epssDate: (json(by.epss?.cursor).date as string) ?? null,
    osvAt: by.osv_mal?.updated_at ?? null,
  };
}

/** Tier 3 (throwaway malicious packages) is shown as a count per ecosystem instead of one item each. */
export async function bulkMalwareCounts(env: Env, since: string) {
  return (
    await env.DB.prepare(
      `SELECT a.ecosystem, COUNT(DISTINCT t.id) AS n FROM threats t JOIN affected a ON a.threat_id = t.id
       WHERE t.tier = 3 AND t.kind = 'malicious_package' AND t.status = 'active' AND t.first_seen >= ?
       GROUP BY a.ecosystem ORDER BY n DESC`,
    )
      .bind(since)
      .all<{ ecosystem: string; n: number }>()
  ).results;
}
