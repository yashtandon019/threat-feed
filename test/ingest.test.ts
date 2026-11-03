import { createExecutionContext } from 'cloudflare:test';
import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kevRecords } from '../src/adapters/kev';
import { isCompromised, malRecord } from '../src/adapters/osv_mal';
import { getThreat, listThreats, parseFilters } from '../src/db';
import { rss } from '../src/feeds';
import { computeTier, upsert } from '../src/ingest';
import type { OsvVuln } from '../src/osv';
import type { Env } from '../src/types';
import app from '../src/index';

const E = env as unknown as Env;
const NOW = new Date('2026-11-03T12:00:00Z');

const typosquat: OsvVuln = {
  id: 'MAL-2026-1',
  summary: 'Malicious code in lodahs (npm)',
  details: 'Steals tokens.\n---\nboilerplate',
  aliases: ['GHSA-aaaa-bbbb-cccc'],
  modified: '2026-11-03T10:00:00Z',
  published: '2026-11-03T09:00:00Z',
  affected: [{ package: { ecosystem: 'npm', name: 'lodahs' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
};
const hijacked: OsvVuln = {
  id: 'MAL-2025-47141',
  summary: 'Malicious code in @ctrl/tinycolor (npm)',
  aliases: ['GHSA-qjqf-7j6f-82c4'],
  modified: '2026-11-03T10:00:00Z',
  affected: [
    {
      package: { ecosystem: 'npm', name: '@ctrl/tinycolor' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '4.1.1' }, { last_affected: '4.1.2' }] }],
      versions: ['4.1.1', '4.1.2'],
    },
  ],
};
const tjGhsa: OsvVuln = {
  id: 'GHSA-mrrh-fwg8-r2c3',
  summary: 'tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets',
  aliases: ['CVE-2025-30066'],
  modified: '2026-11-03T10:00:00Z',
  database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'GitHub Actions', name: 'tj-actions/changed-files' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '46.0.1' }] }] }],
};

/** Fake OSV: /v1/vulns/{id} and /v1/querybatch. */
function stubOsv(vulns: Record<string, unknown>, batch: (q: { package: { name: string } }) => string[] = () => []) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.endsWith('/querybatch')) {
      const { queries } = JSON.parse(String(init?.body));
      return Response.json({ results: queries.map((q: never) => ({ vulns: batch(q).map((id) => ({ id })) })) });
    }
    const id = decodeURIComponent(url.split('/vulns/')[1] ?? '');
    return vulns[id] ? Response.json(vulns[id]) : new Response('not found', { status: 404 });
  });
}

afterEach(() => vi.restoreAllMocks());

describe('tiering', () => {
  it('separates hijacked versions from day-one malware', () => {
    expect(isCompromised(malRecord(hijacked).affected)).toBe(true);
    expect(isCompromised(malRecord(typosquat).affected)).toBe(false);
    // Versions-only entries (dependency confusion, typosquats) depend on the registry count.
    const versionsOnly = [{ ecosystem: 'npm', package: 'hs-framework', ranges: [], versions: ['999.9.1'] }];
    expect(isCompromised(versionsOnly)).toBe(false);
    expect(isCompromised(versionsOnly, [3])).toBe(false);
    expect(isCompromised(versionsOnly, [185])).toBe(true);
  });
  it('applies the signal rules', () => {
    expect(computeTier({ kind: 'compromised_package' }, NOW)).toBe(1);
    expect(computeTier({ kind: 'malicious_package' }, NOW)).toBe(3);
    const kev = { dateAdded: '2026-11-01', dueDate: '', ransomware: false, requiredAction: '' };
    expect(computeTier({ kind: 'exploited_vuln', kev }, NOW)).toBe(1);
    expect(computeTier({ kind: 'exploited_vuln', kev: { ...kev, dateAdded: '2026-10-01' } }, NOW)).toBe(2);
    expect(computeTier({ kind: 'exploited_vuln', epss: 0.7 }, NOW)).toBe(2);
  });
});

describe('ingest and dedupe', () => {
  it('skips unchanged records and keeps tier 3 out of the default feed', async () => {
    expect(await upsert(E, malRecord(typosquat), NOW)).toBe('MAL-2026-1');
    expect(await upsert(E, malRecord(typosquat), NOW)).toBeNull();
    expect(await upsert(E, malRecord(hijacked), NOW)).toBe('MAL-2025-47141');
    const feed = await listThreats(E, parseFilters({ since: '30d' }, NOW));
    expect(feed.map((t) => t.id)).toContain('MAL-2025-47141');
    expect(feed.map((t) => t.id)).not.toContain('MAL-2026-1');
    expect((await getThreat(E, 'GHSA-aaaa-bbbb-cccc'))?.id).toBe('MAL-2026-1');
  });

  it('links a KEV CVE to its package through OSV and merges threats that share an alias', async () => {
    stubOsv({ 'CVE-2025-30066': { id: 'CVE-2025-30066', aliases: ['GHSA-mrrh-fwg8-r2c3'], modified: '' }, 'GHSA-mrrh-fwg8-r2c3': tjGhsa });
    // Threat A arrives first under its GHSA id (as an OSV record would).
    const a = { ...malRecord({ ...tjGhsa, aliases: ['GHSA-mrrh-fwg8-r2c3'] }), source: 'test', sourceId: 'GHSA-mrrh-fwg8-r2c3' };
    await upsert(E, a, NOW);
    // Then KEV lists the CVE; OSV says CVE-2025-30066 == GHSA-mrrh-fwg8-r2c3, so it must land on the same threat.
    const [kevRec] = kevRecords(
      [{ cveID: 'CVE-2025-30066', vendorProject: 'tj-actions', product: 'changed-files', vulnerabilityName: 'Embedded Malicious Code', dateAdded: '2026-11-02', shortDescription: 'Malicious code leaks secrets.', requiredAction: 'Apply mitigations.', dueDate: '2026-11-23', knownRansomwareCampaignUse: 'Unknown' }],
      NOW,
    );
    expect(await upsert(E, kevRec, NOW)).toBe('GHSA-mrrh-fwg8-r2c3');
    const t = await getThreat(E, 'CVE-2025-30066');
    expect(t?.id).toBe('GHSA-mrrh-fwg8-r2c3');
    expect(t?.kind).toBe('poisoned_action');
    expect(t?.tier).toBe(1);
    expect(t?.title).toBe('tj-actions changed-files: Embedded Malicious Code');
    expect(t?.sources.map((s) => s.name).sort()).toEqual(['kev', 'test']);
    expect(t?.affected[0]).toMatchObject({ package: 'tj-actions/changed-files', fixed: ['46.0.1'] });
  });

  it('merges two existing threats when a record bridges them', async () => {
    const x = { ...malRecord({ ...typosquat, id: 'MAL-X', aliases: [] }), aliases: ['MAL-X'] };
    const y = { ...malRecord({ ...typosquat, id: 'MAL-Y', aliases: [] }), aliases: ['MAL-Y'] };
    await upsert(E, x, NOW);
    await upsert(E, y, new Date(NOW.getTime() + 1000));
    await upsert(E, { ...x, source: 'bridge', sourceId: 'B', aliases: ['MAL-X', 'MAL-Y'] }, NOW);
    expect((await getThreat(E, 'MAL-Y'))?.id).toBe('MAL-X');
    const n = await E.DB.prepare("SELECT COUNT(*) AS n FROM threats WHERE id IN ('MAL-X','MAL-Y')").first<{ n: number }>();
    expect(n?.n).toBe(1);
  });
});

describe('outputs', () => {
  it('escapes attacker-controlled text in RSS', () => {
    const xml = rss([{ id: 'X', url: 'u', kind: 'malicious_package', tier: 1, severity: 'critical', title: '<script>', summary: 'a & b', summary_source: 'template', affected: [], epss: null, kev: null, first_seen: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }], 's', 's');
    expect(xml).toContain('&lt;script&gt;');
    expect(xml).toContain('a &amp; b');
    expect(xml).not.toContain('<script>');
  });

  it('check reports hijacked versions and any known MAL hit, with fixes', async () => {
    await upsert(E, malRecord(hijacked), NOW);
    stubOsv({ 'MAL-2025-47141': hijacked, 'MAL-OLD': { ...typosquat, id: 'MAL-OLD' } }, (q) =>
      q.package.name === '@ctrl/tinycolor' ? ['MAL-2025-47141'] : q.package.name === 'old-bad' ? ['MAL-OLD'] : ['GHSA-not-active'],
    );
    const res = await app.fetch(
      new Request('http://x/api/v1/check', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          packages: [
            { ecosystem: 'npm', name: '@ctrl/tinycolor', version: '4.1.1' },
            { ecosystem: 'npm', name: 'old-bad', version: '1.0.0' },
            { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
          ],
        }),
      }),
      E,
    );
    const body = (await res.json()) as { scanned: number; matches: { name: string; fix: object }[] };
    expect(body.scanned).toBe(3);
    expect(body.matches.map((m) => [m.name, m.fix])).toEqual([
      ['@ctrl/tinycolor', { action: 'pin-away', avoid_versions: ['4.1.1', '4.1.2'] }],
      ['old-bad', { action: 'remove' }],
    ]);
  });

  it('serves the feed page, llms.txt and the MCP tool list', async () => {
    expect((await app.fetch(new Request('http://x/'), E, createExecutionContext())).status).toBe(200);
    expect(await (await app.fetch(new Request('http://x/llms.txt'), E, createExecutionContext())).text()).toContain('check_dependencies');
    const mcp = await app.fetch(
      new Request('http://x/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
      }),
      E,
    );
    expect(mcp.status).toBe(200);
  });
});
