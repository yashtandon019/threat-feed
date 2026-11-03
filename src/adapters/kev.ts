import type { Adapter, SourceRecord } from '../types';

const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const WINDOW_DAYS = 30;

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

export function kevRecords(entries: KevEntry[], now: Date): SourceRecord[] {
  const since = new Date(now.getTime() - WINDOW_DAYS * 864e5).toISOString().slice(0, 10);
  return entries
    .filter((e) => e.dateAdded >= since)
    .map((e) => ({
      source: 'kev',
      sourceId: e.cveID,
      aliases: [e.cveID],
      kind: 'exploited_vuln',
      title: `${e.vendorProject} ${e.product}: ${e.vulnerabilityName}`,
      details: e.shortDescription,
      severity: 'high',
      affected: [],
      url: `https://nvd.nist.gov/vuln/detail/${e.cveID}`,
      published: e.dateAdded,
      kev: {
        dateAdded: e.dateAdded,
        dueDate: e.dueDate,
        ransomware: e.knownRansomwareCampaignUse === 'Known',
        requiredAction: e.requiredAction,
      },
    }));
}

/** Re-emits every entry added in the last 30 days when the catalog changes; unchanged ones are skipped by hash. */
export const kev: Adapter = {
  name: 'kev',
  async run(_env, cursor, now) {
    const prev = cursor ? (JSON.parse(cursor) as { etag?: string; version?: string }) : {};
    const res = await fetch(URL, { headers: prev.etag ? { 'If-None-Match': prev.etag } : {} });
    if (res.status === 304) return { records: [], cursor };
    if (!res.ok) throw new Error(`KEV: ${res.status}`);
    const body = (await res.json()) as { catalogVersion: string; vulnerabilities: KevEntry[] };
    const next = JSON.stringify({ etag: res.headers.get('etag') ?? undefined, version: body.catalogVersion });
    if (body.catalogVersion === prev.version) return { records: [], cursor: next };
    return { records: kevRecords(body.vulnerabilities, now), cursor: next };
  },
};
