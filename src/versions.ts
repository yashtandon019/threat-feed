import * as pep440 from '@renovatebot/pep440';
import semver from 'semver';
import type { OsvRange } from './types';

const SEMVER_ECOS = new Set(['npm', 'crates.io', 'Go', 'GitHub Actions']);

/** Ecosystem-aware compare; null where we don't have a comparator (Maven, NuGet, RubyGems, Packagist). */
export function compareVersions(ecosystem: string, a: string, b: string): number | null {
  if (SEMVER_ECOS.has(ecosystem)) {
    const pa = semver.parse(a.replace(/^v/, ''), { loose: true });
    const pb = semver.parse(b.replace(/^v/, ''), { loose: true });
    return pa && pb ? semver.compare(pa, pb) : null;
  }
  if (ecosystem === 'PyPI') {
    return pep440.valid(a) && pep440.valid(b) ? pep440.compare(a, b) : null;
  }
  return null;
}

/**
 * Walks OSV range events (sorted ascending) the way the OSV spec defines them.
 * Needed for GitHub Actions, where OSV's own querybatch does no range matching.
 */
export function isAffected(ecosystem: string, version: string, ranges: OsvRange[], versions: string[]): boolean {
  if (versions.includes(version)) return true;
  const cmp = (a: string, b: string) => compareVersions(ecosystem, a, b);
  return ranges.some((r) => {
    let affected = false;
    for (const e of r.events) {
      if (e.introduced !== undefined && (e.introduced === '0' || (cmp(version, e.introduced) ?? -1) >= 0)) affected = true;
      if (e.fixed !== undefined && (cmp(version, e.fixed) ?? -1) >= 0) affected = false;
      if (e.last_affected !== undefined && (cmp(version, e.last_affected) ?? -1) > 0) affected = false;
    }
    return affected;
  });
}

/** The lowest fixed version above `version` that no range or listed version still covers; undefined if none or no comparator. */
export function nearestSafe(ecosystem: string, version: string, ranges: OsvRange[], versions: string[] = []): string | undefined {
  const fixed = ranges.flatMap((r) => r.events.map((e) => e.fixed).filter((f): f is string => !!f));
  let best: string | undefined;
  for (const f of fixed) {
    if ((compareVersions(ecosystem, f, version) ?? -1) <= 0) continue;
    if (isAffected(ecosystem, f, ranges, versions)) continue;
    if (!best || (compareVersions(ecosystem, f, best) ?? 1) < 0) best = f;
  }
  return best;
}

/** Package names as each registry compares them. */
export function samePackage(ecosystem: string, a: string, b: string): boolean {
  if (ecosystem === 'PyPI') return a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-');
  if (ecosystem === 'GitHub Actions') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}
