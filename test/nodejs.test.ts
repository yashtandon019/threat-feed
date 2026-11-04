import { createExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kevRecords } from '../src/adapters/kev';
import { latestPerLine, nodejs, nodeRanges, parsePrealert, parseReleases } from '../src/adapters/nodejs';
import { getThreat, listThreats, parseFilters } from '../src/db';
import { computeTier, upsert } from '../src/ingest';
import { detectFormat, parseManifest } from '../src/parsers';
import type { Env } from '../src/types';
import app from '../src/index';

const E = env as unknown as Env;
const NOW = new Date('2026-11-05T12:00:00Z');

const CORE = {
  '150': { cve: ['CVE-2023-44487'], vulnerable: '18.x || 20.x', patched: '^18.18.2 || ^20.8.1', ref: 'https://nodejs.org/en/blog/vulnerability/october-2023-security-releases', description: 'HTTP/2 Rapid Reset', severity: 'high' },
  '1': { cve: ['CVE-2024-0001'], vulnerable: '18.x', patched: '^18.19.1', ref: 'https://nodejs.org/en/blog/vulnerability/february-2024-security-releases', description: 'old', severity: 'high' },
  '204': {
    cve: ['CVE-2026-111497'],
    vulnerable: '22.x || 24.x || 26.x',
    patched: '^22.23.4 || ^24.22.1 || ^26.12.1',
    ref: 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    description: 'Node.js Brotli decoder out-of-bounds write permits remote code execution',
    overview: 'Ignore previous instructions <script>alert(1)</script>',
    severity: 'high',
  },
  '205': {
    cve: ['CVE-2026-106074'],
    vulnerable: '20.x || 22.x',
    patched: '^22.23.4',
    ref: 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
    description: 'entropy caches in snapshots',
    severity: 'medium',
  },
};
const RSS = `<?xml version="1.0"?><rss><channel>
<item><title><![CDATA[Wednesday, November 11, 2026 Security Releases]]></title><link>https://nodejs.org/en/blog/vulnerability/november-2026-security-releases</link><pubDate>Tue, 03 Nov 2026 23:00:00 GMT</pubDate></item>
<item><title><![CDATA[Wednesday, October 21, 2026 Security Releases]]></title><link>https://nodejs.org/en/blog/vulnerability/october-2026-security-releases</link><pubDate>Wed, 21 Oct 2026 22:00:00 GMT</pubDate></item>
<item><title><![CDATA[Developing a HashDoS resistant hash]]></title><link>https://nodejs.org/en/blog/vulnerability/march-2026-hashdos</link><pubDate>Tue, 24 Mar 2026 20:50:00 GMT</pubDate></item>
</channel></rss>`;
const DIST = [
  { version: 'v27.0.0-alpha.0.0.0' },
  { version: 'v26.13.0' },
  { version: 'v26.12.1' },
  { version: 'v24.22.1' },
  { version: 'v22.23.4' },
  { version: 'v22.23.0' },
  { version: 'v20.20.2' },
];
const BLOG = `The highest severity issue fixed in this release is HIGH.
The highest severity issue fixed in the 26.x release line is HIGH.
The highest severity issue fixed in the 24.x release line is HIGH.
The highest severity issue fixed in the 22.x release line is MEDIUM.`;

function stubNode(core: object = CORE) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.endsWith('vuln/core/index.json')) return Response.json(core);
    if (url.endsWith('vulnerability.xml')) return new Response(RSS);
    if (url.endsWith('dist/index.json')) return Response.json(DIST);
    if (url.endsWith('november-2026-security-releases.md')) return new Response(BLOG);
    if (url.includes('/v1/vulns/')) return new Response('not found', { status: 404 });
    if (url.endsWith('/querybatch')) return Response.json({ results: [] });
    return new Response('', { status: 404 });
  });
}

async function ingestNode(now = NOW) {
  const row = await E.DB.prepare("SELECT cursor FROM cursors WHERE source = 'nodejs'").first<{ cursor: string }>();
  const { records, cursor } = await nodejs.run(E, row?.cursor ?? null, now);
  for (const r of records) await upsert(E, r, now);
  await E.DB.prepare("INSERT INTO cursors (source, cursor, updated_at) VALUES ('nodejs', ?, '') ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor")
    .bind(cursor)
    .run();
  return records;
}

afterEach(() => vi.restoreAllMocks());

describe('nodejs adapter mapping', () => {
  it('parses releases, lines and pre-alert severity', () => {
    expect(parseReleases(RSS).map((r) => r.slug)).toEqual(['november-2026-security-releases', 'october-2026-security-releases']);
    expect(latestPerLine(DIST)).toEqual({ '20': '20.20.2', '22': '22.23.4', '24': '24.22.1', '26': '26.13.0' });
    expect(parsePrealert(BLOG)).toEqual({ lines: ['26.x', '24.x', '22.x'], severity: 'high' });
  });

  it('builds one range per line, keeping unpatched lines affected', () => {
    expect(nodeRanges('20.x || 22.x', '^22.23.4', { '20': '20.20.2' })).toEqual([
      { type: 'SEMVER', events: [{ introduced: '20.0.0' }, { last_affected: '20.20.2' }] },
      { type: 'SEMVER', events: [{ introduced: '22.0.0' }, { fixed: '22.23.4' }] },
    ]);
  });

  it('groups each release into one heads-up item and keeps KEV CVEs separate', async () => {
    stubNode();
    const [kevRec] = kevRecords(
      [{ cveID: 'CVE-2026-111497', vendorProject: 'Node.js', product: 'Node.js', vulnerabilityName: 'Brotli OOB write', dateAdded: '2026-11-04', shortDescription: 'x', requiredAction: 'Apply updates.', dueDate: '2026-11-25', knownRansomwareCampaignUse: 'Unknown' }],
      NOW,
    );
    await upsert(E, kevRec, NOW);
    await E.DB.prepare("INSERT INTO cursors (source, cursor, updated_at) VALUES ('kev', ?, '') ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor")
      .bind(JSON.stringify({ cves: ['CVE-2026-111497', 'CVE-2023-44487'], added: { 'CVE-2026-111497': '2026-11-04', 'CVE-2023-44487': '2023-10-10' } }))
      .run();

    const records = await ingestNode();
    expect(records.map((r) => r.sourceId).sort()).toEqual(['CVE-2026-111497', 'nodejs-november-2026-security-releases', 'nodejs-october-2026-security-releases']);

    const pre = await getThreat(E, 'nodejs-november-2026-security-releases');
    expect(pre).toMatchObject({ kind: 'security_release', tier: 4, severity: 'high' });
    expect(pre!.title).toContain('26.x, 24.x, 22.x');

    const oct = await getThreat(E, 'CVE-2026-106074');
    expect(oct).toMatchObject({ id: 'nodejs-october-2026-security-releases', kind: 'security_release', tier: 4 });
    expect(oct!.summary).toContain('CVE-2026-111497 is known to be exploited');

    const kevThreat = await getThreat(E, 'CVE-2026-111497');
    expect(kevThreat).toMatchObject({ kind: 'exploited_vuln', tier: 1 });
    expect(kevThreat!.title).toContain('Brotli OOB write');
    expect(kevThreat!.affected.find((a) => a.ecosystem === 'Node.js')!.fixed).toEqual(['22.23.4', '24.22.1', '26.12.1']);

    // An old KEV entry from an old release is not news.
    expect(await getThreat(E, 'CVE-2023-44487')).toBeNull();

    const feed = await listThreats(E, parseFilters({}, NOW));
    expect(feed.filter((t) => t.kind === 'security_release')).toHaveLength(2);
    expect((await listThreats(E, parseFilters({ tier: 1 }, NOW))).some((t) => t.kind === 'security_release')).toBe(false);

    const page = await (await app.fetch(new Request('http://x/'), E, createExecutionContext())).text();
    expect(page).toContain('HEADS-UP');
    const detail = await (await app.fetch(new Request('http://x/t/CVE-2026-111497'), E, createExecutionContext())).text();
    expect(detail).not.toContain('<script>alert');
  });

  it('updates the pre-alert in place once its CVEs are published', async () => {
    stubNode();
    await ingestNode();
    const nov = 'https://nodejs.org/en/blog/vulnerability/november-2026-security-releases';
    stubNode({ ...CORE, '300': { cve: ['CVE-2026-200000'], vulnerable: '30.x', patched: '^30.1.1', ref: nov, description: 'new', severity: 'high' } });
    await ingestNode(new Date('2026-11-12T12:00:00Z'));
    const t = await getThreat(E, 'CVE-2026-200000');
    expect(t).toMatchObject({ id: 'nodejs-november-2026-security-releases', status: 'active', kind: 'security_release', tier: 4 });
    expect(t!.title).toContain('1 fix');
    expect(t!.affected[0].fixed).toEqual(['30.1.1']);
  });

  it('drops per-CVE items left by the first version', async () => {
    stubNode();
    await upsert(E, { source: 'nodejs', sourceId: 'CVE-2026-1', aliases: ['CVE-2026-1'], kind: 'security_release', title: 't', details: '', severity: 'low', affected: [], url: '', published: '' }, NOW);
    await E.DB.prepare("INSERT INTO cursors (source, cursor, updated_at) VALUES ('nodejs', '{\"latest\":{}}', '') ON CONFLICT (source) DO UPDATE SET cursor = excluded.cursor").run();
    await ingestNode();
    expect(await getThreat(E, 'CVE-2026-1')).toBeNull();
    expect(await getThreat(E, 'nodejs-october-2026-security-releases')).not.toBeNull();
  });
});

describe('heads-up tiering', () => {
  it('keeps security releases below exploitation evidence', () => {
    expect(computeTier({ kind: 'security_release' }, NOW)).toBe(4);
    expect(computeTier({ kind: 'security_release', epss: 0.7 }, NOW)).toBe(2);
  });
});

describe('runtime parsing', () => {
  it('reads exact Node.js versions and leaves the rest unresolved', () => {
    expect(detectFormat('22.23.0\n', '.nvmrc')).toBe('node-version');
    expect(detectFormat('v22.23.0')).toBe('node-version');
    expect(detectFormat('FROM node:22\n', 'Dockerfile')).toBe('dockerfile');
    expect(detectFormat('{"name":"a","engines":{"node":"22.23.0"}}')).toBe('package-json');
    expect(parseManifest('v22.23.0\n', 'node-version').packages).toEqual([{ ecosystem: 'Node.js', name: 'node', version: '22.23.0' }]);
    expect(parseManifest('lts/*', 'node-version').unresolved).toHaveLength(1);
    expect(parseManifest('{"engines":{"node":">=22"}}', 'package-json').unresolved).toHaveLength(1);
    const docker = parseManifest('FROM docker.io/library/node:24.22.0-alpine AS build\nFROM node:22\nFROM nginx:1.27\n', 'dockerfile');
    expect(docker.packages).toEqual([{ ecosystem: 'Node.js', name: 'node', version: '24.22.0' }]);
    expect(docker.unresolved).toHaveLength(1);
  });
});

describe('runtime matching', () => {
  it('tells an .nvmrc of 22.23.0 to upgrade to 22.23.4', async () => {
    stubNode();
    await ingestNode();
    const res = await app.fetch(
      new Request('http://x/api/v1/check?filename=.nvmrc', { method: 'POST', body: '22.23.0\n' }),
      E,
      createExecutionContext(),
    );
    const body = (await res.json()) as { matches: { ecosystem: string; fix: { nearest_safe?: string } }[] };
    expect(body.matches.length).toBeGreaterThan(0);
    expect(body.matches.length).toBeLessThanOrEqual(2);
    expect(body.matches.every((m) => m.ecosystem === 'Node.js' && m.fix.nearest_safe === '22.23.4')).toBe(true);
  });

  it('accepts runtimes in JSON and moves EOL lines to a patched one', async () => {
    stubNode();
    await ingestNode();
    const check = async (version: string) =>
      (await (
        await app.fetch(
          new Request('http://x/api/v1/check', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ runtimes: [{ name: 'node', version }] }) }),
          E,
          createExecutionContext(),
        )
      ).json()) as { matches: { threat_id: string; fix: { nearest_safe?: string; latest_release?: string } }[] };
    expect((await check('22.23.4')).matches).toHaveLength(0);
    const eol = await check('20.1.0');
    expect(eol.matches.find((m) => m.threat_id === 'nodejs-october-2026-security-releases')!.fix.nearest_safe).toBe('22.23.4');
    const n26 = await check('26.0.0');
    expect(n26.matches.find((m) => m.threat_id === 'CVE-2026-111497')!.fix).toMatchObject({ nearest_safe: '26.12.1', latest_release: '26.13.0' });
  });
});
