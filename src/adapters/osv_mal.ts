import { affectedOf, getVuln, severityOf, type OsvVuln } from '../osv';
import { ECOSYSTEMS, type Adapter, type Affected, type Kind, type SourceRecord } from '../types';
import { isAffected } from '../versions';

const BUCKET = 'https://storage.googleapis.com/osv-vulnerabilities';
const FIRST_RUN_DAYS = 3;
const MAX_PER_ECOSYSTEM = 40;

// ponytail: release count is a proxy for "real project"; add download counts if hijacks of small packages slip through.
export const CLEAN_RELEASES_FOR_HIJACK = 10;

/** Releases still on the registry that are not flagged. npm and PyPI delete malware-only packages, so a hijacked real project keeps many. */
export async function cleanReleaseCount(a: Affected): Promise<number | null> {
  let releases: string[];
  if (a.ecosystem === 'npm') {
    const res = await fetch(`https://registry.npmjs.org/${a.package.replace('/', '%2f')}`, {
      headers: { accept: 'application/vnd.npm.install-v1+json' },
    });
    if (res.status === 404) return 0;
    if (!res.ok) return null;
    releases = Object.keys(((await res.json()) as { versions?: object }).versions ?? {});
  } else if (a.ecosystem === 'PyPI') {
    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(a.package)}/json`);
    if (res.status === 404) return 0;
    if (!res.ok) return null;
    releases = Object.keys(((await res.json()) as { releases?: object }).releases ?? {});
  } else return null;
  return releases.filter((v) => !isAffected(a.ecosystem, v, a.ranges, a.versions) && !v.includes('security')).length;
}

/**
 * A real package hijacked for some versions, as opposed to one that was malicious from day one.
 * Uses the registry count when known, else whether the advisory starts at a version other than 0.
 */
export function isCompromised(affected: Affected[], cleanReleases: (number | null)[] = []): boolean {
  return affected.some((a, i) => {
    const n = cleanReleases[i];
    if (n !== null && n !== undefined) return n >= CLEAN_RELEASES_FOR_HIJACK;
    return a.ranges.some((r) => r.events.some((e) => e.introduced && e.introduced !== '0'));
  });
}

export function malKind(affected: Affected[], cleanReleases: (number | null)[] = []): Kind {
  if (affected.some((a) => a.ecosystem === 'GitHub Actions')) return 'poisoned_action';
  return isCompromised(affected, cleanReleases) ? 'compromised_package' : 'malicious_package';
}

export async function malRecordWithRegistry(v: OsvVuln): Promise<SourceRecord> {
  const rec = malRecord(v);
  const counts = await Promise.all(rec.affected.map((a) => cleanReleaseCount(a).catch(() => null)));
  return { ...rec, kind: malKind(rec.affected, counts) };
}

export function malRecord(v: OsvVuln): SourceRecord {
  const affected = affectedOf(v);
  return {
    source: 'osv',
    sourceId: v.id,
    aliases: [v.id, ...(v.aliases ?? [])],
    kind: malKind(affected),
    title: v.summary ?? v.id,
    // OSV appends per-source boilerplate after this marker.
    details: (v.details ?? '').split('\n---\n')[0].trim(),
    severity: severityOf(v) === 'unknown' ? 'critical' : severityOf(v),
    affected,
    url: `https://osv.dev/vulnerability/${v.id}`,
    refs: (v.references ?? []).filter((r) => r.type !== 'ADVISORY').map((r) => r.url),
    published: v.published ?? v.modified,
    withdrawn: !!v.withdrawn,
  };
}

/** Reads modified_id.csv (newest first) down to and including the saved timestamp; returns MAL ids oldest first. */
async function newMalIds(ecosystem: string, since: string): Promise<{ id: string; ts: string }[]> {
  const res = await fetch(`${BUCKET}/${encodeURIComponent(ecosystem)}/modified_id.csv`);
  if (!res.ok || !res.body) throw new Error(`OSV ${ecosystem} modified_id.csv: ${res.status}`);
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const out: { id: string; ts: string }[] = [];
  let buf = '';
  read: for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    const lines = buf.split('\n');
    buf = lines.pop()!;
    for (const line of lines) {
      const [ts, id] = line.split(',');
      if (!id || ts < since) break read;
      if (id.startsWith('MAL-')) out.push({ id, ts });
    }
  }
  await reader.cancel();
  return out.reverse();
}

/** Per ecosystem: the last timestamp read and the ids already done at it, since many ids can share one timestamp. */
type Cursor = Record<string, { ts: string; ids: string[] }>;

export const osvMal: Adapter = {
  name: 'osv_mal',
  async run(_env, cursor, now) {
    const raw: Record<string, string | { ts: string; ids: string[] }> = cursor ? JSON.parse(cursor) : {};
    const prev: Cursor = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, typeof v === 'string' ? { ts: v, ids: [] } : v]));
    const firstRun = new Date(now.getTime() - FIRST_RUN_DAYS * 864e5).toISOString();
    const next: Cursor = { ...prev };
    const records: SourceRecord[] = [];
    for (const eco of ECOSYSTEMS) {
      const p = prev[eco] ?? { ts: firstRun, ids: [] };
      const done = new Set(p.ids);
      const ids = (await newMalIds(eco, p.ts)).filter((x) => !(x.ts === p.ts && done.has(x.id))).slice(0, MAX_PER_ECOSYSTEM);
      const vulns = await Promise.all(ids.map((x) => getVuln(x.id)));
      records.push(...(await Promise.all(vulns.filter((v): v is OsvVuln => !!v).map(malRecordWithRegistry))));
      if (ids.length) {
        const ts = ids[ids.length - 1].ts;
        next[eco] = { ts, ids: [...(ts === p.ts ? p.ids : []), ...ids.filter((x) => x.ts === ts).map((x) => x.id)] };
      }
    }
    return { records, cursor: JSON.stringify(next) };
  },
};
