import { describe, expect, it } from 'vitest';
import { detectFormat, parseActions, parseManifest, parsePnpmKey } from '../src/parsers';
import type { OsvRange } from '../src/types';
import { describeRanges } from '../src/db';
import { isAffected, nearestSafe, samePackage } from '../src/versions';

const PACKAGE_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/@ctrl/tinycolor': { version: '4.1.1' },
    'node_modules/a/node_modules/lodash': { version: '4.17.21' },
    'node_modules/local': { link: true },
  },
});

const PNPM_LOCK = `lockfileVersion: '9.0'
packages:
  lodash@4.17.15:
    resolution: {integrity: sha512-x}
  '@ctrl/tinycolor@4.1.1':
    resolution: {integrity: sha512-y}
  /old-style/1.2.3:
    resolution: {integrity: sha512-z}
`;

const POETRY = `[[package]]
name = "Django"
version = "3.2.0"

[[package]]
name = "requests"
version = "2.31.0"
`;

describe('parsers', () => {
  it('reads package-lock v3 including nested copies, skipping root and links', () => {
    const { packages } = parseManifest(PACKAGE_LOCK, 'package-lock');
    expect(packages).toEqual([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
      { ecosystem: 'npm', name: '@ctrl/tinycolor', version: '4.1.1' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
    ]);
  });

  it('reads pnpm v9, v6 and v5 keys', () => {
    expect(parseManifest(PNPM_LOCK, 'pnpm-lock').packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      'lodash@4.17.15',
      '@ctrl/tinycolor@4.1.1',
      'old-style@1.2.3',
    ]);
    expect(parsePnpmKey('/react-dom@18.2.0(react@18.2.0)')).toEqual({ ecosystem: 'npm', name: 'react-dom', version: '18.2.0' });
  });

  it('only trusts pinned requirements', () => {
    const r = parseManifest('Django==3.2.0  # web\nrequests[socks]==2.31.0 ; python_version>"3"\nflask>=2\n-r other.txt\n', 'requirements');
    expect(r.packages).toEqual([
      { ecosystem: 'PyPI', name: 'django', version: '3.2.0' },
      { ecosystem: 'PyPI', name: 'requests', version: '2.31.0' },
    ]);
    expect(r.unresolved.map((u) => u.entry)).toEqual(['flask>=2', '-r other.txt']);
  });

  it('reads poetry.lock and go.sum', () => {
    expect(parseManifest(POETRY, 'poetry-lock').packages.map((p) => p.name)).toEqual(['django', 'requests']);
    const go = parseManifest('golang.org/x/net v0.0.1 h1:abc=\ngolang.org/x/net v0.0.1/go.mod h1:def=\n', 'go-sum');
    expect(go.packages).toEqual([{ ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.0.1' }]);
  });

  it('matches exact action tags and flags moving refs', () => {
    const r = parseActions(['- uses: tj-actions/changed-files@v45.0.7', 'actions/checkout@v4', `foo/bar@${'a'.repeat(40)}`, './local-action@v1']);
    expect(r.packages).toEqual([{ ecosystem: 'GitHub Actions', name: 'tj-actions/changed-files', version: '45.0.7' }]);
    expect(r.unresolved).toHaveLength(2);
  });

  it('detects formats from content', () => {
    expect(detectFormat(PACKAGE_LOCK)).toBe('package-lock');
    expect(detectFormat(PNPM_LOCK)).toBe('pnpm-lock');
    expect(detectFormat(POETRY)).toBe('poetry-lock');
    expect(detectFormat('golang.org/x/net v0.0.1 h1:abc=')).toBe('go-sum');
    expect(detectFormat('Django==3.2.0')).toBe('requirements');
  });
});

describe('review regressions', () => {
  it('keeps pnpm package names that contain underscores', () => {
    expect(parsePnpmKey('evil_pkg@1.0.0')).toEqual({ ecosystem: 'npm', name: 'evil_pkg', version: '1.0.0' });
    expect(parsePnpmKey('/@scope/evil_pkg@1.0.0')).toEqual({ ecosystem: 'npm', name: '@scope/evil_pkg', version: '1.0.0' });
    expect(parsePnpmKey('/foo/1.0.0_react@17.0.0')).toEqual({ ecosystem: 'npm', name: 'foo', version: '1.0.0' });
  });

  it('reads real uses: values, so comments and run lines cannot hide or fake an action', () => {
    const wf = 'jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45.0.7 # docker://x\n      - run: echo me@example.com\n';
    const r = parseManifest(wf, 'actions');
    expect(r.packages).toEqual([{ ecosystem: 'GitHub Actions', name: 'tj-actions/changed-files', version: '45.0.7' }]);
    expect(r.unresolved).toEqual([]);
    expect(parseActions(['owner/repo@v1.2.3/branch']).packages).toEqual([]);
  });

  it('describes the affected set as a union', () => {
    expect(describeRanges([{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }], ['1.0.0'])).toBe('< 2.0.0 or 1.0.0');
    expect(describeRanges([{ type: 'SEMVER', events: [{ introduced: '1' }, { fixed: '2' }, { introduced: '3' }, { fixed: '4' }] }], [])).toBe('>= 1, < 2 or >= 3, < 4');
  });

  it('compares PyPI names the way pip does', () => {
    expect(samePackage('PyPI', 'Foo_Bar', 'foo-bar')).toBe(true);
  });
});

describe('nearestSafe', () => {
  const ranges: OsvRange[] = [
    { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] },
    { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.18.0' }] },
  ];
  it('picks the lowest fixed version above the installed one', () => {
    // 4.17.21 still falls inside the second range, so it is not safe.
    expect(nearestSafe('npm', '4.17.15', ranges)).toBe('4.18.0');
    expect(nearestSafe('npm', '4.17.21', ranges)).toBe('4.18.0');
  });
  it('uses PEP 440 ordering for PyPI', () => {
    const py: OsvRange[] = [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.2.10' }, { fixed: '3.2.9' }] }];
    expect(nearestSafe('PyPI', '3.2.0', py)).toBe('3.2.9');
  });
  it('returns undefined without a comparator', () => {
    expect(nearestSafe('Maven', '1.0', [{ type: 'ECOSYSTEM', events: [{ fixed: '2.0' }] }])).toBeUndefined();
  });
});

describe('isAffected', () => {
  const r: OsvRange[] = [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.5.0' }, { introduced: '2.0.0' }, { last_affected: '2.1.0' }] }];
  it('walks introduced/fixed/last_affected events', () => {
    expect(['1.0.0', '1.5.0', '1.9.0', '2.0.0', '2.1.0', '2.1.1'].map((v) => isAffected('GitHub Actions', v, r, []))).toEqual([true, false, false, true, true, false]);
    expect(isAffected('GitHub Actions', '9.9.9', [], ['9.9.9'])).toBe(true);
  });
});
