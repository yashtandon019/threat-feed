import { ECOSYSTEMS, type Affected, type Severity } from './types';

const API = 'https://api.osv.dev/v1';

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  related?: string[];
  published?: string;
  modified: string;
  withdrawn?: string;
  affected?: { package?: { ecosystem: string; name: string }; ranges?: Affected['ranges']; versions?: string[] }[];
  database_specific?: { severity?: string };
  references?: { type: string; url: string }[];
}

export async function getVuln(id: string): Promise<OsvVuln | null> {
  const res = await fetch(`${API}/vulns/${encodeURIComponent(id)}`, { cf: { cacheTtl: 3600 } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`OSV ${id}: ${res.status}`);
  return res.json();
}

export interface OsvQuery {
  package: { ecosystem: string; name: string };
  /** Omit to get every advisory for the package. */
  version?: string;
}

/** Returns OSV vuln ids per query, in input order. */
export async function queryBatch(queries: OsvQuery[]): Promise<string[][]> {
  const out: string[][] = [];
  for (let i = 0; i < queries.length; i += 1000) {
    let pending = queries.slice(i, i + 1000).map((q, j) => ({ q, idx: i + j, token: undefined as string | undefined }));
    pending.forEach((p) => (out[p.idx] = []));
    while (pending.length) {
      const res = await fetch(`${API}/querybatch`, {
        method: 'POST',
        body: JSON.stringify({ queries: pending.map((p) => ({ ...p.q, page_token: p.token })) }),
      });
      if (!res.ok) throw new Error(`OSV querybatch: ${res.status}`);
      const { results } = (await res.json()) as { results: { vulns?: { id: string }[]; next_page_token?: string }[] };
      results.forEach((r, j) => out[pending[j].idx].push(...(r.vulns ?? []).map((v) => v.id)));
      pending.forEach((p, j) => (p.token = results[j].next_page_token));
      pending = pending.filter((p) => p.token);
    }
  }
  return out;
}

export function affectedOf(v: OsvVuln): Affected[] {
  return (v.affected ?? [])
    .filter((a) => a.package && ECOSYSTEMS.includes(a.package.ecosystem))
    .map((a) => ({
      ecosystem: a.package!.ecosystem,
      package: a.package!.name,
      ranges: (a.ranges ?? []).filter((r) => r.type !== 'GIT'),
      versions: a.versions ?? [],
    }));
}

export function severityOf(v: OsvVuln): Severity {
  const s = v.database_specific?.severity?.toLowerCase();
  if (s === 'moderate') return 'medium';
  return (['critical', 'high', 'medium', 'low'] as const).find((x) => x === s) ?? 'unknown';
}

/** CVE -> GHSA aliases -> affected packages. KEV and EPSS only give CVE ids. */
export async function linkCve(cve: string) {
  const rec = await getVuln(cve);
  // Not `related`: those are other advisories that merely mention the CVE, and would merge unrelated threats.
  const aliases = new Set([cve, ...(rec?.aliases ?? [])]);
  const affected: Affected[] = rec ? affectedOf(rec) : [];
  let severity: Severity = rec ? severityOf(rec) : 'unknown';
  let summary = rec?.summary;
  for (const id of [...aliases].filter((a) => a.startsWith('GHSA-'))) {
    const g = await getVuln(id);
    if (!g) continue;
    affected.push(...affectedOf(g));
    if (severity === 'unknown') severity = severityOf(g);
    summary ??= g.summary;
  }
  return { aliases: [...aliases], affected, severity, summary };
}
