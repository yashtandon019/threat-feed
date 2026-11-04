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

export const FORMATS = ['package-lock', 'pnpm-lock', 'requirements', 'poetry-lock', 'go-sum', 'actions', 'node-version', 'package-json', 'dockerfile'] as const;
export type Format = (typeof FORMATS)[number];

export function detectFormat(text: string, filename = ''): Format | null {
  const f = filename.toLowerCase();
  if (f.endsWith('package-lock.json') || f.endsWith('npm-shrinkwrap.json')) return 'package-lock';
  if (f.endsWith('pnpm-lock.yaml')) return 'pnpm-lock';
  if (f.endsWith('poetry.lock')) return 'poetry-lock';
  if (f.endsWith('go.sum')) return 'go-sum';
  if (f.endsWith('.nvmrc') || f.endsWith('.node-version')) return 'node-version';
  if (f.endsWith('package.json')) return 'package-json';
  if (/(^|\/)dockerfile[^/]*$|\.dockerfile$/.test(f)) return 'dockerfile';
  if (f.endsWith('.txt')) return 'requirements';
  if (f.includes('.github/workflows') || f.endsWith('.yml')) return 'actions';
  const head = text.trimStart().slice(0, 400);
  if (head.startsWith('{') && head.includes('"lockfileVersion"')) return 'package-lock';
  if (head.startsWith('{') && text.includes('"engines"')) return 'package-json';
  if (/^v?\d+(\.\d+){0,2}\s*$/.test(text.trim()) || /^lts\//.test(text.trim())) return 'node-version';
  if (/^\s*FROM\s+\S/im.test(text)) return 'dockerfile';
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

/** pnpm keys: v9 `name@1.0.0`, v6 `/name@1.0.0`, v5 `/name/1.0.0`, each optionally with a `(peer@x)` or v5 `_peer@x` suffix. */
export function parsePnpmKey(key: string): Pkg | null {
  const k = key.replace(/^\//, '').replace(/\(.*$/, '');
  // v5 `name/1.0.0_peer@x` first; otherwise names can't contain '@' after a scope, so the first '@' past index 0 starts the version.
  const v5 = k.match(/^((?:@[^/]+\/)?[^/@]+)\/(\d[^/]*)$/);
  const at = k.indexOf('@', 1);
  const [name, version] = v5 ? [v5[1], v5[2]] : at > 0 ? [k.slice(0, at), k.slice(at + 1)] : [];
  return name && version ? { ecosystem: 'npm', name, version: version.replace(/_.*$/, '') } : null;
}

export function parsePnpmLock(text: string): Parsed {
  const lock = parseYaml(text) as { packages?: Record<string, unknown> };
  const out: Parsed = { packages: [], unresolved: [] };
  for (const key of Object.keys(lock.packages ?? {})) {
    const p = parsePnpmKey(key);
    if (p && /^\d/.test(p.version)) out.packages.push(p);
    else out.unresolved.push({ entry: key, reason: 'not a registry package with an exact version' });
  }
  out.packages = dedupe(out.packages);
  return out;
}

export function parseRequirements(text: string): Parsed {
  const out: Parsed = { packages: [], unresolved: [] };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s#.*$/, '').split(';')[0].trim();
    if (!line || line.startsWith('#')) continue;
    if (/^(-r|-c|-e|--requirement|--constraint|--editable)\b/.test(line)) {
      out.unresolved.push({ entry: line, reason: 'includes or editable installs are not followed; check that file or package separately' });
      continue;
    }
    if (line.startsWith('-')) continue;
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

/** Accepts `owner/repo@ref`, `owner/repo/path@ref` or `uses:` values. Only exact semver tags can be matched. */
export function parseActions(lines: string[]): Parsed {
  const out: Parsed = { packages: [], unresolved: [] };
  for (const raw of lines) {
    const ref0 = raw.replace(/(^|\s)#.*$/, '').trim().replace(/^-\s*/, '').replace(/^uses:\s*/, '').replace(/^(['"])(.*)\1$/, '$2');
    if (!ref0 || ref0.startsWith('./') || ref0.startsWith('docker://')) continue;
    const m = ref0.match(/^([\w.-]+\/[\w.-]+)(?:\/[^@\s]*)?@(\S+)$/);
    if (!m) {
      out.unresolved.push({ entry: ref0, reason: 'not an owner/repo@ref action reference' });
      continue;
    }
    const [, name, ref] = m;
    if (/^v?\d+\.\d+\.\d+$/.test(ref)) out.packages.push({ ecosystem: 'GitHub Actions', name, version: ref.replace(/^v/, '') });
    else if (/^[0-9a-f]{40}$/.test(ref))
      out.unresolved.push({ entry: ref0, reason: 'commit SHA pins are not resolved to tags yet; check the threat list for this action manually' });
    else out.unresolved.push({ entry: ref0, reason: `"${ref}" is a moving tag, branch or non-exact ref; pin an exact version or SHA to check it` });
  }
  out.packages = dedupe(out.packages);
  return out;
}

/** Every `uses:` value in a workflow or action file; falls back to raw lines when the text isn't YAML. */
function usesValues(text: string): string[] {
  let doc: unknown;
  try {
    doc = parseYaml(text);
  } catch {
    return text.split('\n').filter((l) => l.includes('@'));
  }
  if (!doc || typeof doc !== 'object') return text.split('\n').filter((l) => l.includes('@'));
  const out: string[] = [];
  const walk = (n: unknown) => {
    if (Array.isArray(n)) n.forEach(walk);
    else if (n && typeof n === 'object')
      for (const [k, v] of Object.entries(n)) {
        if (k === 'uses' && typeof v === 'string') out.push(v);
        else walk(v);
      }
  };
  walk(doc);
  return out;
}

/** One Node.js version string; only exact x.y.z can be matched. */
export function nodeVersion(raw: string, where: string): Parsed {
  const v = raw.trim().replace(/^[v=]+/, '');
  if (/^\d+\.\d+\.\d+$/.test(v)) return { packages: [{ ecosystem: 'Node.js', name: 'node', version: v }], unresolved: [] };
  return { packages: [], unresolved: [{ entry: `${where}: node ${raw.trim()}`, reason: 'not an exact Node.js version (x.y.z); pin one to check it' }] };
}

export function parseNodeVersionFile(text: string): Parsed {
  const line = text.split('\n').map((l) => l.replace(/#.*$/, '').trim()).find(Boolean) ?? '';
  return nodeVersion(line, '.nvmrc');
}

export function parsePackageJsonEngines(text: string): Parsed {
  const node = (JSON.parse(text) as { engines?: { node?: unknown } }).engines?.node;
  return typeof node === 'string' ? nodeVersion(node, 'package.json engines') : { packages: [], unresolved: [] };
}

/** `FROM node:<tag>` lines, including registry prefixes and `AS` stages. */
export function parseDockerfile(text: string): Parsed {
  const out: Parsed = { packages: [], unresolved: [] };
  for (const m of text.matchAll(/^\s*FROM\s+(?:--\S+\s+)*(?:[\w.-]+(?::\d+)?\/)?(?:library\/)?node(?::([^\s@]+))?(?:@\S+)?(?:\s|$)/gim)) {
    const tag = m[1] ?? 'latest';
    const version = tag.match(/^v?(\d+\.\d+\.\d+)(?:-|$)/)?.[1];
    const p = nodeVersion(version ?? tag, 'Dockerfile FROM');
    out.packages.push(...p.packages);
    out.unresolved.push(...p.unresolved);
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
      return parseActions(usesValues(text));
    case 'node-version':
      return parseNodeVersionFile(text);
    case 'package-json':
      return parsePackageJsonEngines(text);
    case 'dockerfile':
      return parseDockerfile(text);
  }
}
