import { epss } from './adapters/epss';
import { ghsa } from './adapters/ghsa';
import { kev } from './adapters/kev';
import { nodejs } from './adapters/nodejs';
import { osvMal } from './adapters/osv_mal';
import { linkCve } from './osv';
import { templateSummary } from './summarize';
import type { Adapter, Affected, Env, Kind, Severity, SourceRecord } from './types';

export const ADAPTERS: Adapter[] = [kev, epss, ghsa, osvMal, nodejs];
export const KEV_HOT_DAYS = 14;

const KIND_RANK: Kind[] = ['security_release', 'runtime_vuln', 'exploited_vuln', 'malicious_package', 'compromised_package', 'poisoned_action'];
const SEV_RANK: Severity[] = ['unknown', 'low', 'medium', 'high', 'critical'];

export interface Merged {
  aliases: string[];
  kind: Kind;
  title: string;
  details: string;
  severity: Severity;
  affected: Affected[];
  epss?: number;
  kev?: SourceRecord['kev'];
  withdrawn: boolean;
}

export function computeTier(t: Pick<Merged, 'kind' | 'kev' | 'epss'>, now: Date): 1 | 2 | 3 | 4 {
  if (t.kind === 'poisoned_action' || t.kind === 'compromised_package') return 1;
  if (t.kev && now.getTime() - Date.parse(t.kev.dateAdded) <= KEV_HOT_DAYS * 864e5) return 1;
  if (t.kev || (t.epss ?? 0) >= 0.5) return 2;
  // Heads-up: runtime fixes and release pre-alerts with no sign of exploitation.
  if (t.kind === 'runtime_vuln' || t.kind === 'security_release') return 4;
  return 3;
}

/** Combines every source record of one threat. KEV wording wins for titles, MAL records for kind. */
export function merge(records: SourceRecord[]): Merged {
  const byPkg = new Map<string, Affected>();
  for (const a of records.flatMap((r) => r.affected)) {
    const key = `${a.ecosystem}\0${a.package}`;
    const cur = byPkg.get(key);
    if (!cur) byPkg.set(key, { ...a, ranges: [...a.ranges], versions: [...a.versions] });
    else {
      cur.ranges.push(...a.ranges.filter((r) => !cur.ranges.some((c) => JSON.stringify(c) === JSON.stringify(r))));
      cur.versions = [...new Set([...cur.versions, ...a.versions])];
    }
  }
  const kevRec = records.find((r) => r.kev);
  const titled = kevRec ?? records.find((r) => r.title !== r.sourceId) ?? records[0];
  let kind = records.map((r) => r.kind).reduce((a, b) => (KIND_RANK.indexOf(b) > KIND_RANK.indexOf(a) ? b : a));
  if (kind === 'exploited_vuln' && kevRec && [...byPkg.values()].some((a) => a.ecosystem === 'GitHub Actions')) {
    kind = 'poisoned_action';
  }
  return {
    aliases: [...new Set(records.flatMap((r) => r.aliases))],
    kind,
    title: titled.title,
    details: [...new Set(records.map((r) => r.details).filter(Boolean))].join('\n\n'),
    severity: records.map((r) => r.severity).reduce((a, b) => (SEV_RANK.indexOf(b) > SEV_RANK.indexOf(a) ? b : a)),
    affected: [...byPkg.values()],
    epss: records.map((r) => r.epss).find((e) => e !== undefined),
    kev: kevRec?.kev,
    withdrawn: records.every((r) => r.withdrawn),
  };
}

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function placeholders(n: number) {
  return Array(n).fill('?').join(',');
}

export async function upsert(env: Env, rec: SourceRecord, now: Date): Promise<string | null> {
  const db = env.DB;
  const ts = now.toISOString();
  const hash = await sha256(JSON.stringify(rec));
  const prev = await db
    .prepare('SELECT content_hash FROM source_records WHERE source = ? AND source_id = ?')
    .bind(rec.source, rec.sourceId)
    .first<{ content_hash: string }>();
  if (prev?.content_hash === hash) return null;

  if (rec.kind === 'exploited_vuln' && !rec.affected.length) {
    const linked = await linkCve(rec.sourceId);
    rec = {
      ...rec,
      aliases: [...new Set([...rec.aliases, ...linked.aliases])],
      affected: linked.affected,
      severity: rec.severity === 'unknown' ? linked.severity : rec.severity,
      title: rec.title === rec.sourceId && linked.summary ? linked.summary : rec.title,
    };
  }
  if (rec.needsPackage && !rec.affected.length) return null;

  // Dedupe: every alias points at one threat. A record that bridges several threats merges them into the oldest.
  const found = new Map<string, string>();
  for (let i = 0; i < rec.aliases.length; i += 90) {
    const chunk = rec.aliases.slice(i, i + 90); // D1 allows 100 bound parameters per statement
    const rows = await db
      .prepare(
        `SELECT DISTINCT t.id, t.first_seen FROM aliases a JOIN threats t ON t.id = a.threat_id
         WHERE a.alias IN (${placeholders(chunk.length)})`,
      )
      .bind(...chunk)
      .all<{ id: string; first_seen: string }>();
    for (const r of rows.results) found.set(r.id, r.first_seen);
  }
  const hits = [...found].map(([id, first_seen]) => ({ id, first_seen })).sort((a, b) => a.first_seen.localeCompare(b.first_seen) || a.id.localeCompare(b.id));
  const id = hits[0]?.id ?? rec.sourceId;
  const firstSeen = hits[0]?.first_seen ?? ts;
  const absorbed = hits.slice(1).map((h) => h.id);

  // Merge from what's stored for this threat and any it absorbs, with this record in place of its old version.
  const owners = [id, ...absorbed];
  const stored = (
    await db
      .prepare(`SELECT source, source_id, record_json FROM source_records WHERE threat_id IN (${placeholders(owners.length)})`)
      .bind(...owners)
      .all<{ source: string; source_id: string; record_json: string }>()
  ).results.filter((r) => !(r.source === rec.source && r.source_id === rec.sourceId));
  const m = merge([...stored.map((r) => JSON.parse(r.record_json) as SourceRecord), rec]);
  const contentHash = await sha256(JSON.stringify(m));
  const tier = computeTier(m, now);
  const ph = placeholders(absorbed.length);

  // One batch is one transaction: the source hash is only stored if the threat lands too, so a failed run retries.
  await db.batch([
    ...(absorbed.length
      ? [
          db.prepare(`UPDATE aliases SET threat_id = ? WHERE threat_id IN (${ph})`).bind(id, ...absorbed),
          db.prepare(`UPDATE source_records SET threat_id = ? WHERE threat_id IN (${ph})`).bind(id, ...absorbed),
          db.prepare(`DELETE FROM affected WHERE threat_id IN (${ph})`).bind(...absorbed),
          db.prepare(`DELETE FROM threats WHERE id IN (${ph})`).bind(...absorbed),
        ]
      : []),
    db
      .prepare(
        `INSERT INTO source_records (source, source_id, threat_id, url, content_hash, record_json, fetched_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (source, source_id) DO UPDATE SET threat_id = excluded.threat_id, url = excluded.url,
           content_hash = excluded.content_hash, record_json = excluded.record_json, fetched_at = excluded.fetched_at`,
      )
      .bind(rec.source, rec.sourceId, id, rec.url, hash, JSON.stringify(rec), ts),
    db
      .prepare(
        `INSERT INTO threats (id, kind, tier, title, severity, details, summary, summary_model, summary_hash, content_hash,
           epss, kev_added, kev_due, ransomware, status, first_seen, updated_at, last_signal_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'template', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET kind = excluded.kind, tier = excluded.tier, title = excluded.title,
           severity = excluded.severity, details = excluded.details, content_hash = excluded.content_hash,
           epss = excluded.epss, kev_added = excluded.kev_added, kev_due = excluded.kev_due,
           ransomware = excluded.ransomware, status = excluded.status, updated_at = excluded.updated_at,
           last_signal_at = excluded.last_signal_at,
           summary = CASE WHEN threats.summary_model = 'template' THEN excluded.summary ELSE threats.summary END`,
      )
      .bind(
        id, m.kind, tier, m.title, m.severity, m.details, templateSummary(m), contentHash,
        m.epss ?? null, m.kev?.dateAdded ?? null, m.kev?.dueDate ?? null, m.kev?.ransomware ? 1 : 0,
        m.withdrawn ? 'withdrawn' : 'active', firstSeen, ts, ts,
      ),
    db.prepare('DELETE FROM affected WHERE threat_id = ?').bind(id),
    ...m.affected.map((a) =>
      db
        .prepare('INSERT INTO affected (threat_id, ecosystem, package, ranges_json, versions_json) VALUES (?, ?, ?, ?, ?)')
        .bind(id, a.ecosystem, a.package, JSON.stringify(a.ranges), JSON.stringify(a.versions)),
    ),
    ...[id, ...m.aliases].map((alias) =>
      db
        .prepare('INSERT INTO aliases (alias, threat_id) VALUES (?, ?) ON CONFLICT (alias) DO UPDATE SET threat_id = excluded.threat_id')
        .bind(alias, id),
    ),
  ]);
  return id;
}

export async function runIngest(env: Env, now = new Date()) {
  const results: { source: string; records: number; changed: number; error?: string }[] = [];
  for (const adapter of ADAPTERS) {
    try {
      const row = await env.DB.prepare('SELECT cursor FROM cursors WHERE source = ?').bind(adapter.name).first<{ cursor: string }>();
      const { records, cursor } = await adapter.run(env, row?.cursor ?? null, now);
      let changed = 0;
      for (const r of records) if (await upsert(env, r, now)) changed++;
      if (cursor !== null) {
        await env.DB.prepare(
          'INSERT INTO cursors (source, cursor, updated_at) VALUES (?, ?, ?) ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at',
        )
          .bind(adapter.name, cursor, now.toISOString())
          .run();
      }
      console.log(`ingest ${adapter.name}: ${records.length} records, ${changed} changed`);
      results.push({ source: adapter.name, records: records.length, changed });
    } catch (err) {
      // The cursor is saved only after every record lands, so the next run retries from the same point.
      console.error(`ingest ${adapter.name} failed`, err);
      results.push({ source: adapter.name, records: 0, changed: 0, error: String(err) });
    }
  }
  await ageTiers(env, now);
  return results;
}

/** Tiers are computed on change; KEV entries also age out of tier 1 with time alone. */
export async function ageTiers(env: Env, now: Date) {
  await env.DB.prepare(
    "UPDATE threats SET tier = 2 WHERE tier = 1 AND kind = 'exploited_vuln' AND kev_added IS NOT NULL AND kev_added < ?",
  )
    .bind(new Date(now.getTime() - KEV_HOT_DAYS * 864e5).toISOString().slice(0, 10))
    .run();
}
