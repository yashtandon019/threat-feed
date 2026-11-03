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

/** The lowest fixed version above `version` across all ranges, or undefined if none or no comparator. */
export function nearestSafe(ecosystem: string, version: string, ranges: OsvRange[]): string | undefined {
  const fixed = ranges.flatMap((r) => r.events.map((e) => e.fixed).filter((f): f is string => !!f));
  let best: string | undefined;
  for (const f of fixed) {
    if ((compareVersions(ecosystem, f, version) ?? -1) <= 0) continue;
    if (!best || (compareVersions(ecosystem, f, best) ?? 1) < 0) best = f;
  }
  return best;
}
