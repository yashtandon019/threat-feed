import type { Adapter, Affected, Env, OsvRange, SourceRecord } from '../types';
import { cleanReleaseCount, malKind } from './osv_mal';

const API = 'https://api.github.com/advisories';
const FIRST_RUN_HOURS = 24;
const MAX_PAGES = 3;

// GitHub's ecosystem names -> OSV's.
const ECOSYSTEM: Record<string, string> = {
  npm: 'npm',
  pip: 'PyPI',
  go: 'Go',
  rust: 'crates.io',
  maven: 'Maven',
  nuget: 'NuGet',
  rubygems: 'RubyGems',
  composer: 'Packagist',
  actions: 'GitHub Actions',
};

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  description: string | null;
  published_at: string;
  updated_at: string;
  withdrawn_at: string | null;
  vulnerabilities: { package: { ecosystem: string; name: string } | null; vulnerable_version_range: string | null; first_patched_version: string | null }[];
}

/**
 * GitHub ranges look like ">= 0", "= 4.1.1", ">= 1.0, < 1.2.3" or "<= 2.0".
 * ponytail: ">" is treated as ">="; exact for malware ranges, which never use it, close enough otherwise.
 */
export function parseGhsaRange(range: string | null, patched: string | null): { ranges: OsvRange[]; versions: string[] } {
  const parts = (range ?? '>= 0').split(',').map((s) => s.trim()).filter(Boolean);
  const versions: string[] = [];
  let introduced = '0';
  let fixed = patched ?? undefined;
  let last: string | undefined;
  for (const p of parts) {
    const m = p.match(/^(>=|>|<=|<|=)\s*(.+)$/);
    if (!m) continue;
    const [, op, v] = m;
    if (op === '=') versions.push(v);
    else if (op === '>=' || op === '>') introduced = v;
    else if (op === '<') fixed = v;
    else last = v;
  }
  if (versions.length && versions.length === parts.length) return { ranges: [], versions };
  const events: Record<string, string>[] = [{ introduced }];
  if (fixed) events.push({ fixed });
  else if (last) events.push({ last_affected: last });
  return { ranges: [{ type: 'ECOSYSTEM', events }], versions };
}

export function ghsaRecord(a: GhsaAdvisory): SourceRecord {
  const affected: Affected[] = a.vulnerabilities
    .filter((v) => v.package && ECOSYSTEM[v.package.ecosystem])
    .map((v) => ({ ecosystem: ECOSYSTEM[v.package!.ecosystem], package: v.package!.name, ...parseGhsaRange(v.vulnerable_version_range, v.first_patched_version) }));
  return {
    source: 'ghsa',
    sourceId: a.ghsa_id,
    aliases: [a.ghsa_id, ...(a.cve_id ? [a.cve_id] : [])],
    kind: malKind(affected),
    title: a.summary,
    details: a.description ?? '',
    severity: 'critical',
    affected,
    url: a.html_url,
    published: a.published_at,
    withdrawn: !!a.withdrawn_at,
  };
}

/** GitHub's malware advisories, read directly: minutes behind GitHub instead of OSV's ~1 hour import lag. */
export const ghsa: Adapter = {
  name: 'ghsa',
  async run(env: Env, cursor, now) {
    const since = cursor ?? new Date(now.getTime() - FIRST_RUN_HOURS * 3600e3).toISOString();
    const headers: Record<string, string> = {
      accept: 'application/vnd.github+json',
      'user-agent': 'compromised-live',
      'x-github-api-version': '2022-11-28',
    };
    if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;

    // Oldest first from the cursor (inclusive), so a capped run resumes where it stopped instead of skipping.
    const fresh: GhsaAdvisory[] = [];
    let url: string | null = `${API}?type=malware&sort=updated&direction=asc&per_page=100&updated=${encodeURIComponent(`>=${since.replace(/\.\d+Z$/, 'Z')}`)}`;
    for (let page = 0; page < MAX_PAGES && url; page++) {
      const res: Response = await fetch(url, { headers });
      if (!res.ok) throw new Error(`GitHub advisories: ${res.status}`);
      fresh.push(...((await res.json()) as GhsaAdvisory[]));
      const next = res.headers.get('link')?.match(/<([^>]+)>;\s*rel="next"/)?.[1] ?? null;
      // Only follow pagination on GitHub's API host, since the request carries the token.
      url = next && new URL(next).origin === new URL(API).origin ? next : null;
    }

    const records = await Promise.all(
      fresh.map(async (a) => {
        const rec = ghsaRecord(a);
        const counts = await Promise.all(rec.affected.map((x) => cleanReleaseCount(x).catch(() => null)));
        return { ...rec, kind: malKind(rec.affected, counts) };
      }),
    );
    return { records, cursor: fresh.at(-1)?.updated_at ?? since };
  },
};
