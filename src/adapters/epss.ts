import type { Adapter, SourceRecord } from '../types';

export const EPSS_THRESHOLD = 0.5;

/**
 * Emits CVEs that newly crossed the EPSS threshold since the previous daily score.
 * The cursor holds the set of CVEs above the threshold (~4.4k ids, ~70 KB).
 * The first run only seeds that set, otherwise every old high-EPSS CVE would flood the feed.
 */
export const epss: Adapter = {
  name: 'epss',
  async run(_env, cursor) {
    const prev = cursor ? (JSON.parse(cursor) as { date: string; cves: string[] }) : null;
    const res = await fetch(`https://api.first.org/data/v1/epss?epss-gt=${EPSS_THRESHOLD}&limit=10000`);
    if (!res.ok) throw new Error(`EPSS: ${res.status}`);
    const { data } = (await res.json()) as { data: { cve: string; epss: string; date: string }[] };
    if (!data.length || data[0].date === prev?.date) return { records: [], cursor };
    const next = JSON.stringify({ date: data[0].date, cves: data.map((d) => d.cve) });
    if (!prev) return { records: [], cursor: next };
    const known = new Set(prev.cves);
    // ponytail: an EPSS model update can shift thousands of scores at once; keep the top 200 so one run stays inside the cron CPU limit.
    const crossed = data.filter((d) => !known.has(d.cve)).sort((a, b) => Number(b.epss) - Number(a.epss)).slice(0, 200);
    const records: SourceRecord[] = crossed.map((d) => ({
        source: 'epss',
        sourceId: d.cve,
        aliases: [d.cve],
        kind: 'exploited_vuln',
        title: d.cve,
        details: `EPSS exploitation probability rose to ${Number(d.epss).toFixed(2)} on ${d.date}.`,
        severity: 'unknown',
        affected: [],
        url: `https://www.first.org/epss/`,
        published: d.date,
        epss: Number(d.epss),
        needsPackage: true,
      }));
    return { records, cursor: next };
  },
};
