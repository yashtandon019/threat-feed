import { isCompromised } from './adapters/osv_mal';
import { affectedOf, getVuln, queryBatch } from './osv';
import { detectFormat, parseActions, parseManifest, type Format, type Pkg, type Unresolved } from './parsers';
import { normalizeEcosystem, type Env } from './types';
import { nearestSafe } from './versions';

export const MAX_MANIFEST_BYTES = 2_000_000;
export const MAX_PACKAGES = 5000;

export interface CheckInput {
  manifest?: string;
  format?: Format;
  filename?: string;
  packages?: { ecosystem: string; name: string; version: string }[];
  actions?: string[];
}

export interface Fix {
  action: 'upgrade' | 'remove' | 'pin-away';
  nearest_safe?: string;
  fixed_versions?: string[];
  avoid_versions?: string[];
}

export interface Match {
  ecosystem: string;
  name: string;
  version: string;
  threat_id: string;
  kind: string;
  tier: number;
  title: string;
  summary: string;
  url: string;
  fix: Fix;
}

export class CheckError extends Error {}

function collect(input: CheckInput): { packages: Pkg[]; unresolved: Unresolved[] } {
  const packages: Pkg[] = [];
  const unresolved: Unresolved[] = [];
  if (input.manifest) {
    if (input.manifest.length > MAX_MANIFEST_BYTES) throw new CheckError(`manifest is over ${MAX_MANIFEST_BYTES} bytes; send packages[] instead`);
    const format = input.format ?? detectFormat(input.manifest, input.filename);
    if (!format) throw new CheckError('could not detect the manifest format; pass format');
    try {
      const p = parseManifest(input.manifest, format);
      packages.push(...p.packages);
      unresolved.push(...p.unresolved);
    } catch (err) {
      throw new CheckError(`could not parse ${format}: ${(err as Error).message}`);
    }
  }
  for (const p of input.packages ?? []) {
    const ecosystem = normalizeEcosystem(p.ecosystem);
    if (ecosystem && p.name && p.version) packages.push({ ecosystem, name: p.name, version: p.version });
    else unresolved.push({ entry: `${p.ecosystem}/${p.name}@${p.version}`, reason: 'unknown ecosystem or missing name/version' });
  }
  if (input.actions?.length) {
    const a = parseActions(input.actions);
    packages.push(...a.packages);
    unresolved.push(...a.unresolved);
  }
  if (packages.length > MAX_PACKAGES) throw new CheckError(`too many packages (${packages.length}, max ${MAX_PACKAGES})`);
  return { packages, unresolved };
}

/**
 * OSV does the per-ecosystem version matching. We keep only hits that are active threats in our feed,
 * plus every MAL- hit: a known malicious package is always worth reporting, even if it predates our window.
 */
export async function checkDependencies(env: Env, input: CheckInput) {
  const { packages, unresolved } = collect(input);
  const hits = await queryBatch(packages.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })));
  const allIds = [...new Set(hits.flat())];

  const active = new Map<string, { id: string; kind: string; tier: number; title: string; summary: string }>();
  for (let i = 0; i < allIds.length; i += 90) {
    const ids = allIds.slice(i, i + 90);
    const rows = (
      await env.DB.prepare(
        `SELECT a.alias, t.id, t.kind, t.tier, t.title, t.summary FROM aliases a JOIN threats t ON t.id = a.threat_id
         WHERE t.status = 'active' AND a.alias IN (${ids.map(() => '?').join(',')})`,
      )
        .bind(...ids)
        .all<{ alias: string; id: string; kind: string; tier: number; title: string; summary: string }>()
    ).results;
    for (const r of rows) active.set(r.alias, r);
  }

  const matches: Match[] = [];
  for (const [i, ids] of hits.entries()) {
    const pkg = packages[i];
    const seen = new Set<string>();
    for (const vulnId of ids) {
      const t = active.get(vulnId);
      if (!t && !vulnId.startsWith('MAL-')) continue;
      if (t && seen.has(t.id)) continue;
      const v = await getVuln(vulnId);
      if (!v || v.withdrawn) continue;
      const aff = affectedOf(v).find((a) => a.ecosystem === pkg.ecosystem && a.package === pkg.name);
      const ranges = aff?.ranges ?? [];
      const fixed = ranges.flatMap((r) => r.events.map((e) => e.fixed).filter((f): f is string => !!f));
      let fix: Fix;
      if (vulnId.startsWith('MAL-') && !fixed.length) {
        const hijacked = t ? t.kind === 'compromised_package' : isCompromised(aff ? [aff] : []);
        fix = hijacked && aff?.versions.length ? { action: 'pin-away', avoid_versions: aff.versions } : { action: 'remove' };
      } else {
        const safe = nearestSafe(pkg.ecosystem, pkg.version, ranges);
        fix = safe ? { action: 'upgrade', nearest_safe: safe } : { action: 'upgrade', fixed_versions: fixed };
      }
      const id = t?.id ?? vulnId;
      seen.add(id);
      matches.push({
        ...pkg,
        threat_id: id,
        kind: t?.kind ?? 'malicious_package',
        tier: t?.tier ?? 1,
        title: t?.title ?? v.summary ?? vulnId,
        summary: t?.summary ?? 'Known malicious package. Remove it and rotate any secrets on machines that installed it.',
        url: `${env.SITE_URL}/t/${encodeURIComponent(id)}`,
        fix,
      });
    }
  }
  matches.sort((a, b) => a.tier - b.tier);
  return { scanned: packages.length, matches, unresolved };
}
