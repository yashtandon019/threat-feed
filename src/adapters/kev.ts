import type { Adapter, Env, SourceRecord } from '../types';

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
      // KEV often repeats the vendor in the product name ("WordPress" + "WordPress Core").
      title: `${e.product.startsWith(e.vendorProject) ? e.product : `${e.vendorProject} ${e.product}`}: ${e.vulnerabilityName}`,
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

interface KevCursor {
  etag?: string;
  version?: string;
  /** Every CVE in the catalog (~1.8k ids), so check_dependencies can flag KEV entries older than the feed window. */
  cves?: string[];
  /** dateAdded per CVE, for sources that link their own records to older KEV entries. */
  added?: Record<string, string>;
}

export async function knownExploitedCves(env: Env): Promise<Set<string>> {
  const row = await env.DB.prepare("SELECT cursor FROM cursors WHERE source = 'kev'").first<{ cursor: string }>();
  return new Set(row ? ((JSON.parse(row.cursor) as KevCursor).cves ?? []) : []);
}

/** Re-emits every entry added in the last 30 days when the catalog changes; unchanged ones are skipped by hash. */
export async function kevDates(env: Env): Promise<Record<string, string>> {
  const row = await env.DB.prepare("SELECT cursor FROM cursors WHERE source = 'kev'").first<{ cursor: string }>();
  return row ? ((JSON.parse(row.cursor) as KevCursor).added ?? {}) : {};
}

export const kev: Adapter = {
  name: 'kev',
  async run(_env, cursor, now) {
    const prev: KevCursor = cursor ? JSON.parse(cursor) : {};
    // Skip the ETag until the CVE list has been stored once, so older cursors get backfilled.
    const res = await fetch(URL, { headers: prev.etag && prev.added ? { 'If-None-Match': prev.etag } : {} });
    if (res.status === 304) return { records: [], cursor };
    if (!res.ok) throw new Error(`KEV: ${res.status}`);
    const body = (await res.json()) as { catalogVersion: string; vulnerabilities: KevEntry[] };
    const next = JSON.stringify({
      etag: res.headers.get('etag') ?? undefined,
      version: body.catalogVersion,
      cves: body.vulnerabilities.map((v) => v.cveID),
      added: Object.fromEntries(body.vulnerabilities.map((v) => [v.cveID, v.dateAdded])),
    } satisfies KevCursor);
    if (body.catalogVersion === prev.version) return { records: [], cursor: next };
    return { records: kevRecords(body.vulnerabilities, now), cursor: next };
  },
};
