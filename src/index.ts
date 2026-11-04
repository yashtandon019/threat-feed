import { Hono, type Context } from 'hono';
import { bearerAuth } from 'hono/bearer-auth';
import { cache } from 'hono/cache';
import { timingSafeEqual } from 'hono/utils/buffer';
import { CheckError, checkDependencies, type CheckInput } from './check';
import { bulkMalwareCounts, getThreat, listThreats, parseFilters, sourceStatus } from './db';
import { atom, jsonFeed, rss } from './feeds';
import { checkPage, feedPage, threatPage } from './html';
import { runIngest } from './ingest';
import { mcpFetch } from './mcp';
import type { Format } from './parsers';
import { summarizeQueued } from './summarize';
import type { Env } from './types';

const app = new Hono<{ Bindings: Env }>();

// www.<site> redirects to the canonical SITE_URL host.
app.use(async (c, next) => {
  const url = new URL(c.req.url);
  const canonical = new URL(c.env.SITE_URL);
  if (url.hostname === `www.${canonical.hostname}`) {
    return c.redirect(`${canonical.origin}${url.pathname}${url.search}`, 301);
  }
  await next();
});

app.all('/mcp', (c) => mcpFetch(c.env, c.req.raw));

// Manual run of the cron job. Awaited in the request: waitUntil work is cut off ~30 s after the response.
app.post(
  '/admin/ingest',
  async (c, next) => (c.env.INGEST_TOKEN ? next() : c.json({ error: 'disabled' }, 404)),
  bearerAuth<{ Bindings: Env }>({ verifyToken: (token, c) => timingSafeEqual(token, c.env.INGEST_TOKEN!) }),
  async (c) => {
    const results = await runIngest(c.env);
    await summarizeQueued(c.env);
    return c.json({ results });
  },
);

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

const site = (env: Env) => ({ name: env.SITE_NAME, url: env.SITE_URL });

// Accepts both ?ecosystem=npm,PyPI and repeated ?ecosystem=npm&ecosystem=PyPI (what HTML forms send).
function filtersFrom(c: Context<{ Bindings: Env }>) {
  const multi = (k: string) => (c.req.queries(k) ?? []).flatMap((v) => v.split(',')).filter(Boolean);
  return parseFilters({ ecosystem: multi('ecosystem'), kind: multi('kind'), tier: c.req.query('tier'), since: c.req.query('since'), limit: c.req.query('limit') });
}

app.post('/check', async (c) => {
  const body = await c.req.parseBody();
  const file = body.file instanceof File && body.file.size ? body.file : undefined;
  const manifest = file ? await file.text() : String(body.manifest ?? '');
  const format = String(body.format ?? '');
  const view = { manifest: file ? '' : manifest, format };
  if (!manifest.trim()) return c.html(checkPage({ ...view, error: 'Paste a lockfile or choose a file first.' }, site(c.env)), 400);
  try {
    const result = await checkDependencies(c.env, { manifest, format: (format || undefined) as Format | undefined, filename: file?.name });
    return c.html(checkPage({ ...view, result }, site(c.env)));
  } catch (err) {
    if (err instanceof CheckError) return c.html(checkPage({ ...view, error: err.message }, site(c.env)), 400);
    throw err;
  }
});

app.get('*', cache({ cacheName: 'threat-feed', cacheControl: 'public, max-age=60' }));

app.get('/', async (c) => {
  const f = filtersFrom(c);
  const since = ['24h', '7d', '30d'].includes(c.req.query('since') ?? '') ? c.req.query('since')! : '7d';
  const [items, bulk, status] = await Promise.all([listThreats(c.env, f), bulkMalwareCounts(c.env, f.since), sourceStatus(c.env)]);
  return c.html(feedPage(items, { ecosystem: f.ecosystems, kind: f.kinds, since }, bulk, f, status, site(c.env)));
});

app.get('/check', (c) => c.html(checkPage({ manifest: '', format: '' }, site(c.env))));

app.get('/t/:id', async (c) => {
  const t = await getThreat(c.env, c.req.param('id'));
  return t ? c.html(threatPage(t, site(c.env))) : c.notFound();
});

app.get('/api/v1/threats', async (c) => c.json({ generated_at: new Date().toISOString(), items: await listThreats(c.env, filtersFrom(c)) }));

app.get('/api/v1/threats/:id', async (c) => {
  const t = await getThreat(c.env, c.req.param('id'));
  return t ? c.json(t) : c.json({ error: 'not found' }, 404);
});

app.get('/feed.xml', async (c) => {
  const items = await listThreats(c.env, filtersFrom(c));
  return c.body(rss(items, c.req.url, c.env.SITE_URL), 200, { 'content-type': 'application/rss+xml; charset=utf-8' });
});
app.get('/feed.atom', async (c) => {
  const items = await listThreats(c.env, filtersFrom(c));
  return c.body(atom(items, c.req.url, c.env.SITE_URL), 200, { 'content-type': 'application/atom+xml; charset=utf-8' });
});
app.get('/feed.json', async (c) => {
  const items = await listThreats(c.env, filtersFrom(c));
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
