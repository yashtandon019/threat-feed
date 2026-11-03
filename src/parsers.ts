import { parse as parseToml } from 'smol-toml';
import { parse as parseYaml } from 'yaml';

export interface Pkg {
  ecosystem: string;
  name: string;
  version: string;
}
export interface Unresolved {
  entry: string;
  reason: string;
}
export interface Parsed {
  packages: Pkg[];
  unresolved: Unresolved[];
}

export const FORMATS = ['package-lock', 'pnpm-lock', 'requirements', 'poetry-lock', 'go-sum', 'actions'] as const;
export type Format = (typeof FORMATS)[number];

export function detectFormat(text: string, filename = ''): Format | null {
  const f = filename.toLowerCase();
  if (f.endsWith('package-lock.json') || f.endsWith('npm-shrinkwrap.json')) return 'package-lock';
  if (f.endsWith('pnpm-lock.yaml')) return 'pnpm-lock';
  if (f.endsWith('poetry.lock')) return 'poetry-lock';
  if (f.endsWith('go.sum')) return 'go-sum';
  if (f.endsWith('.txt')) return 'requirements';
  if (f.includes('.github/workflows') || f.endsWith('.yml')) return 'actions';
  const head = text.trimStart().slice(0, 400);
  if (head.startsWith('{') && head.includes('"lockfileVersion"')) return 'package-lock';
  if (/^lockfileVersion:/m.test(head)) return 'pnpm-lock';
  if (head.includes('[[package]]')) return 'poetry-lock';
  if (/^\S+ v\d\S* h1:/m.test(head)) return 'go-sum';
  if (/^\s*(-\s*)?(uses:\s*)?[\w.-]+\/[\w./-]+@\S+/m.test(head)) return 'actions';
  if (/^[A-Za-z0-9._-]+(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<|$)/m.test(head)) return 'requirements';
  return null;
}

function dedupe(pkgs: Pkg[]): Pkg[] {
  const seen = new Set<string>();
  return pkgs.filter((p) => {
    const k = `${p.ecosystem}\0${p.name}\0${p.version}`;
    return !seen.has(k) && !!seen.add(k);
  });
}

export function parsePackageLock(text: string): Parsed {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; link?: boolean; name?: string }>;
    dependencies?: Record<string, { version?: string; dependencies?: object }>;
  };
  const pkgs: Pkg[] = [];
  if (lock.packages) {
    for (const [path, p] of Object.entries(lock.packages)) {
      if (!path || p.link || !p.version) continue;
      const name = p.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      pkgs.push({ ecosystem: 'npm', name, version: p.version });
    }
  } else {
    // lockfileVersion 1
    const walk = (deps: Record<string, { version?: string; dependencies?: object }> = {}) => {
      for (const [name, d] of Object.entries(deps)) {
        if (d.version && !d.version.includes(':')) pkgs.push({ ecosystem: 'npm', name, version: d.version });
        walk(d.dependencies as typeof deps);
      }
    };
    walk(lock.dependencies);
  }
  return { packages: dedupe(pkgs), unresolved: [] };
}

/** pnpm keys: v9 `name@1.0.0`, v6 `/name@1.0.0`, v5 `/name/1.0.0`, each optionally with a `(peer@x)` suffix. */
export function parsePnpmKey(key: string): Pkg | null {
  const k = key.replace(/^\//, '').replace(/\(.*$/, '').replace(/_.*$/, '');
  const at = k.lastIndexOf('@');
  if (at > 0) return { ecosystem: 'npm', name: k.slice(0, at), version: k.slice(at + 1) };
  const slash = k.lastIndexOf('/');
  return slash > 0 ? { ecosystem: 'npm', name: k.slice(0, slash), version: k.slice(slash + 1) } : null;
}

export function parsePnpmLock(text: string): Parsed {
  const lock = parseYaml(text) as { packages?: Record<string, unknown> };
  const pkgs = Object.keys(lock.packages ?? {})
    .map(parsePnpmKey)
    .filter((p): p is Pkg => !!p && /^\d/.test(p.version));
  return { packages: dedupe(pkgs), unresolved: [] };
}

export function parseRequirements(text: string): Parsed {
  const out: Parsed = { packages: [], unresolved: [] };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s#.*$/, '').split(';')[0].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*===?\s*([^\s,]+)$/);
    if (m) out.packages.push({ ecosystem: 'PyPI', name: m[1].toLowerCase(), version: m[3] });
    else out.unresolved.push({ entry: line, reason: 'not pinned with ==, so the installed version is unknown' });
  }
  out.packages = dedupe(out.packages);
  return out;
}

export function parsePoetryLock(text: string): Parsed {
  const lock = parseToml(text) as { package?: { name: string; version: string }[] };
  return {
    packages: dedupe((lock.package ?? []).map((p) => ({ ecosystem: 'PyPI', name: p.name.toLowerCase(), version: p.version }))),
    unresolved: [],
  };
}

export function parseGoSum(text: string): Parsed {
  const pkgs = text
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p.length >= 3)
    .map(([name, version]) => ({ ecosystem: 'Go', name, version: version.replace(/\/go\.mod$/, '') }));
  return { packages: dedupe(pkgs), unresolved: [] };
}

/** Accepts `owner/repo@ref`, `owner/repo/path@ref` or `uses:` lines. Only exact semver tags can be matched. */
export function parseActions(lines: string[]): Parsed {
  const out: Parsed = { packages: [], unresolved: [] };
  for (const raw of lines) {
    const m = raw.match(/([\w.-]+\/[\w.-]+)(?:\/[\w./-]*)?@([\w.-]+)/);
    if (!m || raw.includes('docker://') || raw.trim().startsWith('./')) continue;
    const [, name, ref] = m;
    if (/^v?\d+\.\d+\.\d+/.test(ref)) out.packages.push({ ecosystem: 'GitHub Actions', name, version: ref.replace(/^v/, '') });
    else if (/^[0-9a-f]{40}$/.test(ref))
      out.unresolved.push({ entry: raw.trim(), reason: 'commit SHA pins are not resolved to tags yet; check the threat list for this action manually' });
    else out.unresolved.push({ entry: raw.trim(), reason: `"${ref}" is a moving tag or branch; pin an exact version or SHA to check it` });
  }
  out.packages = dedupe(out.packages);
  return out;
}

export function parseManifest(text: string, format: Format): Parsed {
  switch (format) {
    case 'package-lock':
      return parsePackageLock(text);
    case 'pnpm-lock':
      return parsePnpmLock(text);
    case 'requirements':
      return parseRequirements(text);
    case 'poetry-lock':
      return parsePoetryLock(text);
    case 'go-sum':
      return parseGoSum(text);
    case 'actions':
      return parseActions(text.split('\n').filter((l) => l.includes('@')));
  }
}
