import { Hono } from 'hono';
import { cache } from 'hono/cache';
import { CheckError, checkDependencies, type CheckInput } from './check';
import { bulkMalwareCounts, getThreat, listThreats, parseFilters } from './db';
import { atom, jsonFeed, rss } from './feeds';
import { feedPage, threatPage } from './html';
import { runIngest } from './ingest';
import { mcpFetch } from './mcp';
import type { Format } from './parsers';
import { summarizeQueued } from './summarize';
import type { Env } from './types';

const app = new Hono<{ Bindings: Env }>();

app.all('/mcp', (c) => mcpFetch(c.env, c.req.raw));

app.post('/api/v1/check', async (c) => {
  let input: CheckInput;
  if ((c.req.header('content-type') ?? '').includes('application/json')) {
    input = await c.req.json<CheckInput>().catch(() => ({}));
  } else {
    // Raw lockfile body: curl --data-binary @package-lock.json ".../api/v1/check?filename=package-lock.json"
    input = { manifest: await c.req.text(), format: c.req.query('format') as Format | undefined, filename: c.req.query('filename') };
  }
  try {
    return c.json(await checkDependencies(c.env, input));
  } catch (err) {
    if (err instanceof CheckError) return c.json({ error: err.message }, 400);
    throw err;
  }
});

app.get('*', cache({ cacheName: 'threat-feed', cacheControl: 'public, max-age=60' }));

app.get('/', async (c) => {
  const q = c.req.query();
  const f = parseFilters(q);
  const [items, bulk] = await Promise.all([listThreats(c.env, f), bulkMalwareCounts(c.env, f.since)]);
  return c.html(feedPage(items, q, bulk, f));
});

app.get('/t/:id', async (c) => {
  const t = await getThreat(c.env, c.req.param('id'));
  return t ? c.html(threatPage(t)) : c.notFound();
});

app.get('/api/v1/threats', async (c) => c.json({ generated_at: new Date().toISOString(), items: await listThreats(c.env, parseFilters(c.req.query())) }));

app.get('/api/v1/threats/:id', async (c) => {
  const t = await getThreat(c.env, c.req.param('id'));
  return t ? c.json(t) : c.json({ error: 'not found' }, 404);
});

app.get('/feed.xml', async (c) => {
  const items = await listThreats(c.env, parseFilters(c.req.query()));
  return c.body(rss(items, c.req.url, c.env.SITE_URL), 200, { 'content-type': 'application/rss+xml; charset=utf-8' });
});
app.get('/feed.atom', async (c) => {
  const items = await listThreats(c.env, parseFilters(c.req.query()));
  return c.body(atom(items, c.req.url, c.env.SITE_URL), 200, { 'content-type': 'application/atom+xml; charset=utf-8' });
});
app.get('/feed.json', async (c) => {
  const items = await listThreats(c.env, parseFilters(c.req.query()));
  return c.json(jsonFeed(items, c.req.url, c.env.SITE_URL), 200, { 'content-type': 'application/feed+json; charset=utf-8' });
});

app.get('/llms.txt', (c) => {
  const s = c.env.SITE_URL;
  return c.text(`# Active security threats

> A free, no-login live feed of security threats that are happening now: CISA KEV additions, CVEs with fast-rising EPSS scores, and malicious or hijacked packages and GitHub Actions from OSV (OpenSSF Malicious Packages, GitHub Advisory Database). Updated every 10 minutes.

## MCP server
- Endpoint: ${s}/mcp (Streamable HTTP, no auth)
- list_feed(ecosystem?, kind?, min_tier?, since?, limit?): recent active threats
- get_threat(id): one threat by CVE, GHSA or MAL id
- check_dependencies(packages? | manifest? | actions?): which dependencies match active threats, with the nearest safe version

## JSON API
- GET ${s}/api/v1/threats?ecosystem=npm,PyPI&kind=compromised_package&tier=2&since=7d&limit=50
- GET ${s}/api/v1/threats/{id}
- POST ${s}/api/v1/check  (JSON {packages, manifest, format, actions} or a raw lockfile body with ?filename=)

## Feeds (same query filters)
- ${s}/feed.xml (RSS), ${s}/feed.atom, ${s}/feed.json

## Fields
- tier: 1 act now, 2 elevated, 3 bulk typosquat malware (hidden by default)
- kind: exploited_vuln, malicious_package, compromised_package, poisoned_action
- summary_source: "ai" summaries are generated from source text and can be wrong; "template" summaries are fixed wording
`);
});

export default {
  fetch: app.fetch,
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(runIngest(env).then(() => summarizeQueued(env)));
  },
} satisfies ExportedHandler<Env>;
