import { knownExploitedCves } from './adapters/kev';
import { latestNodeReleases } from './adapters/nodejs';
import { isCompromised } from './adapters/osv_mal';
import { z } from 'zod';
import { describeRanges } from './db';
import { affectedOf, getVuln, queryBatch, type OsvVuln } from './osv';
import { detectFormat, FORMATS, nodeVersion, parseActions, parseManifest, type Format, type Pkg, type Unresolved } from './parsers';
import { normalizeEcosystem, type Affected, type Env } from './types';
import { isAffected, nearestSafe, samePackage } from './versions';

export const MAX_MANIFEST_BYTES = 2_000_000;
export const MAX_PACKAGES = 5000;

/** One schema for the HTTP API and MCP. */
export const checkShape = {
  packages: z
    .array(z.object({ ecosystem: z.string(), name: z.string(), version: z.string() }))
    .max(MAX_PACKAGES)
    .optional()
    .describe('Exact installed versions'),
  manifest: z
    .string()
    .optional()
    .describe('Contents of package-lock.json, pnpm-lock.yaml, requirements.txt, poetry.lock, go.sum, a workflow file, .nvmrc, .node-version, package.json (engines.node) or a Dockerfile'),
  format: z.enum(FORMATS).optional().describe('Detected automatically when omitted'),
  actions: z.array(z.string()).max(MAX_PACKAGES).optional().describe("GitHub Actions refs like 'actions/checkout@v4.1.1'"),
  runtimes: z
    .array(z.object({ name: z.string(), version: z.string() }))
    .max(50)
    .optional()
    .describe("Runtime versions like { name: 'node', version: '22.23.0' }. Only Node.js is supported."),
};
export const checkSchema = z.object({ ...checkShape, filename: z.string().optional() });
export type CheckInput = z.infer<typeof checkSchema>;

export interface Fix {
  action: 'upgrade' | 'remove' | 'pin-away';
  nearest_safe?: string;
  fixed_versions?: string[];
  avoid_versions?: string[];
  /** Affected ranges beyond the listed versions; when set, not every other version is safe. */
  avoid_ranges?: string;
  /** Node.js only: the newest release on the nearest safe version's line. */
  latest_release?: string;
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
  if (!input.packages?.length && !input.manifest?.trim() && !input.actions?.length && !input.runtimes?.length)
    throw new CheckError('pass packages, manifest, actions or runtimes');
  const packages: Pkg[] = [];
  const unresolved: Unresolved[] = [];
  if (input.manifest) {
    if (new TextEncoder().encode(input.manifest).length > MAX_MANIFEST_BYTES) throw new CheckError(`manifest is over ${MAX_MANIFEST_BYTES} bytes; send packages[] instead`);
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
  for (const r of input.runtimes ?? []) {
    if (normalizeEcosystem(r.name) !== 'Node.js') {
      unresolved.push({ entry: `${r.name}@${r.version}`, reason: 'only the node runtime is supported' });
      continue;
    }
    const p = nodeVersion(r.version, 'runtimes');
    packages.push(...p.packages);
    unresolved.push(...p.unresolved);
  }
  if (packages.length > MAX_PACKAGES) throw new CheckError(`too many packages (${packages.length}, max ${MAX_PACKAGES})`);
  return { packages, unresolved };
}

/**
 * OSV does the per-ecosystem version matching. We keep only hits that are active threats in our feed,
 * plus every MAL- hit and every CVE in the full KEV catalog: those are always worth reporting, even if they predate our window.
 */
export async function checkDependencies(env: Env, input: CheckInput) {
  const collected = collect(input);
  const { unresolved } = collected;
  // Runtimes are matched only against our own affected rows (localMatches), so they go last and skip OSV.
  const osvPkgs = collected.packages.filter((p) => p.ecosystem !== 'Node.js');
  const packages = [...osvPkgs, ...collected.packages.filter((p) => p.ecosystem === 'Node.js')];
  // OSV does no range matching for GitHub Actions, so ask for every advisory and filter with isAffected below.
  const hits = await queryBatch(
    osvPkgs.map((p) => ({
      package: { ecosystem: p.ecosystem, name: p.name },
      version: p.ecosystem === 'GitHub Actions' ? undefined : p.version,
    })),
  );
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

  // Older KEV entries aren't in the feed window, but an exploited dependency must never come back clean.
  const kev = await knownExploitedCves(env);
  const toFetch = allIds.filter((id) => active.has(id) || id.startsWith('MAL-') || kev.size);
  const vulns = new Map<string, OsvVuln | null>();
  for (let i = 0; i < toFetch.length; i += 25) {
    const chunk = toFetch.slice(i, i + 25);
    (await Promise.all(chunk.map(getVuln))).forEach((v, j) => vulns.set(chunk[j], v));
  }

  const matches: Match[] = [];
  const seen = packages.map(() => new Set<string>());
  for (const [i, ids] of hits.entries()) {
    const pkg = packages[i];
    for (const vulnId of ids) {
      const t = active.get(vulnId);
      const v = vulns.get(vulnId);
      if (!v || v.withdrawn) continue;
      const isMal = vulnId.startsWith('MAL-');
      const kevCve = [vulnId, ...(v.aliases ?? [])].find((a) => kev.has(a));
      if (!t && !isMal && !kevCve) continue;
      const id = t?.id ?? (isMal ? vulnId : kevCve!);
      if (seen[i].has(id)) continue;
      const aff = combine(affectedOf(v).filter((a) => a.ecosystem === pkg.ecosystem && samePackage(pkg.ecosystem, a.package, pkg.name)));
      if (pkg.ecosystem === 'GitHub Actions' && !(aff && isAffected(pkg.ecosystem, pkg.version, aff.ranges, aff.versions))) continue;
      const hijacked = t ? t.kind === 'compromised_package' : isCompromised(aff ? [aff] : []);
      seen[i].add(id);
      matches.push({
        ...pkg,
        threat_id: id,
        kind: t?.kind ?? (isMal ? 'malicious_package' : 'exploited_vuln'),
        tier: t?.tier ?? (isMal ? 1 : 2),
        title: t?.title ?? v.summary ?? vulnId,
        summary:
          t?.summary ??
          (isMal
            ? 'Known malicious package. Remove it and rotate any secrets on machines that installed it.'
            : `${id} is in CISA's Known Exploited Vulnerabilities catalog: attackers have used it in the wild. Upgrade to a fixed version.`),
        // Only threats in our feed have a page here; the rest link to OSV.
        url: t ? `${env.SITE_URL}/t/${encodeURIComponent(id)}` : `https://osv.dev/vulnerability/${encodeURIComponent(vulnId)}`,
        fix: fixFor(pkg, aff, isMal, hijacked),
      });
    }
  }

  // Our feed can be ahead of OSV (the GHSA adapter reads GitHub directly), so also match against local affected rows.
  for (const m of await localMatches(env, packages, seen)) matches.push(m);

  if (matches.some((m) => m.ecosystem === 'Node.js')) {
    const latest = await latestNodeReleases(env);
    for (const m of matches) {
      const line = m.ecosystem === 'Node.js' && m.fix.nearest_safe?.split('.')[0];
      if (line && latest[line] && latest[line] !== m.fix.nearest_safe) m.fix.latest_release = latest[line];
    }
  }

  matches.sort((a, b) => a.tier - b.tier);
  return { scanned: packages.length, matches, unresolved };
}

function combine(affs: Affected[]): Affected | undefined {
  if (!affs.length) return undefined;
  return { ...affs[0], ranges: affs.flatMap((a) => a.ranges), versions: [...new Set(affs.flatMap((a) => a.versions))] };
}

function fixFor(pkg: Pkg, aff: Affected | undefined, isMal: boolean, hijacked: boolean): Fix {
  const ranges = aff?.ranges ?? [];
  const fixed = ranges.flatMap((r) => r.events.map((e) => e.fixed).filter((f): f is string => !!f));
  if (isMal && !fixed.length) {
    if (!hijacked || !aff?.versions.length) return { action: 'remove' };
    return ranges.length ? { action: 'pin-away', avoid_versions: aff.versions, avoid_ranges: describeRanges(ranges, []) } : { action: 'pin-away', avoid_versions: aff.versions };
  }
  const safe = nearestSafe(pkg.ecosystem, pkg.version, ranges, aff?.versions ?? []);
  return safe ? { action: 'upgrade', nearest_safe: safe } : { action: 'upgrade', fixed_versions: fixed };
}

async function localMatches(env: Env, packages: Pkg[], seen: Set<string>[]): Promise<Match[]> {
  type Row = { ecosystem: string; package: string; ranges_json: string; versions_json: string; id: string; kind: string; tier: number; title: string; summary: string };
  const names = [...new Set(packages.map((p) => p.name.toLowerCase()))];
  const rows: Row[] = [];
  for (let i = 0; i < names.length; i += 90) {
    const chunk = names.slice(i, i + 90);
    rows.push(
      ...(
        await env.DB.prepare(
          `SELECT a.ecosystem, a.package, a.ranges_json, a.versions_json, t.id, t.kind, t.tier, t.title, t.summary
           FROM affected a JOIN threats t ON t.id = a.threat_id
           WHERE t.status = 'active' AND lower(a.package) IN (${chunk.map(() => '?').join(',')})`,
        )
          .bind(...chunk)
          .all<Row>()
      ).results,
    );
  }
  const out: Match[] = [];
  for (const [i, pkg] of packages.entries()) {
    const byThreat = new Map<string, Row[]>();
    for (const r of rows)
      if (r.ecosystem === pkg.ecosystem && samePackage(pkg.ecosystem, r.package, pkg.name) && !seen[i].has(r.id))
        byThreat.set(r.id, [...(byThreat.get(r.id) ?? []), r]);
    for (const [id, rs] of byThreat) {
      const aff = combine(rs.map((r) => ({ ecosystem: r.ecosystem, package: r.package, ranges: JSON.parse(r.ranges_json), versions: JSON.parse(r.versions_json) })))!;
      if (!isAffected(pkg.ecosystem, pkg.version, aff.ranges, aff.versions)) continue;
      const t = rs[0];
      const isMal = t.kind === 'malicious_package' || t.kind === 'compromised_package' || t.kind === 'poisoned_action';
      seen[i].add(id);
      out.push({
        ...pkg,
        threat_id: id,
        kind: t.kind,
        tier: t.tier,
        title: t.title,
        summary: t.summary,
        url: `${env.SITE_URL}/t/${encodeURIComponent(id)}`,
        fix: fixFor(pkg, aff, isMal, t.kind === 'compromised_package'),
      });
    }
  }
  return out;
}
