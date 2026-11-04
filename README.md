# threat-feed

A free, no-login live feed of security threats that are happening now, not every CVE:

- **Exploited vulnerabilities:** new CISA KEV entries (observed exploitation), and CVEs whose EPSS score just crossed 0.5 (a predicted likelihood, only when they map to a package).
- **Supply chain attacks:** malicious and hijacked packages and GitHub Actions, read directly from GitHub's malware advisories (minutes old) and from OSV (OpenSSF Malicious Packages).
- **Node.js runtime:** fixes from the Node.js security WG index and pre-alerts for upcoming Node.js security releases, as low-urgency heads-up items unless KEV lists them.

It serves a web feed, RSS/Atom/JSON Feed, a JSON API, `llms.txt`, and a remote MCP server with a `check_dependencies` tool.

Stack: TypeScript, Hono on Cloudflare Workers, D1, a Cron Trigger every 10 minutes, Claude for summaries.

## Endpoints

| Path | What |
|---|---|
| `/` | Web feed. Query filters: `ecosystem`, `kind`, `tier`, `since` (`24h`, `7d`, `30d` or ISO), `limit` |
| `/t/{id}` | One threat. Any alias works: `CVE-`, `GHSA-`, `MAL-` |
| `/feed.xml`, `/feed.atom`, `/feed.json` | Feeds, same filters |
| `GET /api/v1/threats`, `GET /api/v1/threats/{id}` | JSON API, same filters |
| `POST /api/v1/check` | JSON `{packages, manifest, format, actions, runtimes}`, or a raw body with `?filename=`. Also reads `.nvmrc`, `.node-version`, `package.json` `engines.node` and Dockerfile `FROM node:<version>` |
| `/mcp` | MCP over Streamable HTTP, no auth: `list_feed`, `get_threat`, `check_dependencies` |
| `/llms.txt` | Agent-facing index |
| `/about` | What counts as active, privacy, sources, contact |
| `/health` | 200 when every source (KEV, EPSS, GHSA, OSV, Node.js) ran in the last 30 minutes, else 503 with per-source ages (for uptime monitors) |

```bash
curl -s -X POST "http://localhost:8787/api/v1/check?filename=package-lock.json" --data-binary @package-lock.json
curl -s -X POST "http://localhost:8787/api/v1/check?filename=.nvmrc" --data-binary @.nvmrc
curl -s -X POST http://localhost:8787/api/v1/check -H 'content-type: application/json' -d '{"runtimes":[{"name":"node","version":"22.23.0"}]}'
```

## Signal rules

| Tier | Rule |
|---|---|
| 1, act now | Added to KEV in the last 14 days; a hijacked package (see below); any poisoned GitHub Action |
| 2, elevated | Any other KEV entry from the last 30 days; a CVE that newly crossed EPSS 0.5 and maps to a package |
| 3, bulk | Malicious packages that were malicious from day one (typosquats, dependency confusion). Hidden by default and shown as a count |
| 4, heads-up | Node.js runtime CVEs with no KEV entry or EPSS signal, and Node.js security release pre-alerts (withdrawn once the CVEs are published). Shown unless `tier=1` |

**Hijacked or throwaway?** npm and PyPI delete malware-only packages, so a hijacked real project still has many clean releases. A MAL entry counts as hijacked when the registry lists at least 10 releases outside the flagged versions. Other ecosystems fall back to "the advisory range starts at a version other than 0". Only registry JSON metadata is read; no package is ever downloaded or run.

Threats stay in the default feed for 7 days after their last signal (`since` changes this).

## How it works

```
cron */10 -> adapters (kev, epss, ghsa, osv_mal, nodejs) -> SourceRecord[] -> upsert: hash check, link CVE to packages via OSV,
          dedupe by alias, merge, tier -> D1 -> summarize (tier 1-2 only, when sources change)
request   -> Hono (Cache API, 60 s) -> D1;  check_dependencies -> OSV querybatch -> keep active threats + any MAL hit + any CVE in the full KEV catalog
```

- **Adapters** live in `src/adapters/`, one file per source. Each returns `SourceRecord[]` (see `src/types.ts`) and a cursor string. To add a source, write one adapter and add it to `ADAPTERS` in `src/ingest.ts`.
- **Dedupe:** every CVE, GHSA and MAL id is a row in `aliases`. A record whose aliases point at two threats merges them into the older one; both ids keep resolving.
- **Version matching** is done by OSV (`querybatch`), which handles each ecosystem's version rules. We only compare versions to pick the nearest safe one (semver for npm, Go, crates.io and Actions; PEP 440 for PyPI).
- **Node.js runtime:** the `nodejs` adapter reads the security WG `vuln/core/index.json` (CVEs from releases in the last 30 days, plus any in KEV), the Node.js vulnerability blog RSS (pre-alerts) and `dist/index.json` (latest release per line). Each CVE becomes ecosystem `Node.js`, package `node`, one range per release line. Runtime versions are matched locally with semver, not via OSV.
- **Summaries:** template text for everything, replaced by a 3-sentence Claude summary for tier 1-2. The model only sees source text, fenced as untrusted. A refusal or bad output keeps the template.

## Local development

Requires Node 24 (`nvm use` reads `.nvmrc`). No Cloudflare account is needed locally.

```bash
npm install
npm run db:migrate          # creates the local D1 database
npm run dev                 # http://localhost:8787
```

Run one ingest cycle against the live sources:

```bash
curl "http://localhost:8787/__scheduled?cron=*/10+*+*+*+*"
```

The first run seeds the EPSS baseline (no EPSS items until the next daily score) and reads the last 3 days of OSV malware, 40 per ecosystem per run.

For AI summaries, put your key in `.dev.vars` (git-ignored):

```
ANTHROPIC_API_KEY=sk-ant-...
```

Without a key, every item keeps its template summary. The model is `SUMMARY_MODEL` in `wrangler.jsonc`: Claude Haiku 5.5, the cheapest tier, at well under $1/month for ~20 summaries a day. A refusal keeps the template text.

## Tests

```bash
npm test         # vitest in the Workers runtime, with D1 and stubbed OSV
npm run typecheck
```

## Deploy (personal Cloudflare account)

Needs Workers Paid ($5/month): free-plan cron jobs get 10 ms of CPU.

Credentials are scoped to this repo instead of a global `wrangler login`: wrangler reads `.env` (git-ignored) from the project folder. Create an API token from the "Edit Cloudflare Workers" template, add Account > D1 > Edit, limit it to one account, then:

```
# .env
CLOUDFLARE_API_TOKEN=...
CLOUDFLARE_ACCOUNT_ID=...
```

Keep a `.dev.vars` file (even an empty one): when it is missing, `wrangler dev` passes `.env`, token included, to the local Worker.

```bash
npx wrangler whoami                      # confirm it is the right account
npx wrangler d1 create threat-feed       # copy database_id into wrangler.jsonc (first time only)
npx wrangler d1 migrations apply DB --remote
npx wrangler secret put ANTHROPIC_API_KEY   # optional, enables AI summaries
npx wrangler secret put GITHUB_TOKEN        # optional, avoids GitHub's 60/hour unauthenticated limit
npx wrangler deploy
```

`SITE_URL` in `wrangler.jsonc` is the public URL used in feed and API links; `.dev.vars` overrides it to localhost for local dev.

## CI: fail a build on active threats

```yaml
# .github/workflows/compromised.yml
name: Active threat check
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a full commit SHA
      - name: Check dependencies against active threats
        run: |
          curl -sf --data-binary @package-lock.json \
            "https://compromised.live/api/v1/check?filename=package-lock.json" > result.json
          jq -r '.matches[] | "\(.name)@\(.version): \(.title) (\(.threat_id))"' result.json
          jq -r '.unresolved[] | "not checked: \(.entry) (\(.reason))"' result.json
          # An empty or partial scan is not a pass.
          jq -e '.scanned > 0 and (.matches | length == 0) and (.unresolved | length == 0)' result.json > /dev/null
```

`/api/v1/check` and `/mcp` are rate-limited per IP (20 and 60 requests a minute).

## Reporting problems

False positives, missing threats and wrong summaries: [open an issue](../../issues/new?template=report.yml). Every threat page and check result links to the same form with the id filled in.

## Known limits

- Action refs pinned to a commit SHA or a moving tag (`@v4`) are returned as `unresolved`, not checked.
- Unpinned `requirements.txt` lines are returned as `unresolved`.
- Maven, NuGet, RubyGems and Packagist matches list fixed versions without picking the nearest one.
- Container images are not scanned; only the `node` base image tag in a Dockerfile is read.
- Node.js versions must be exact (`22.23.0`); ranges, `lts/*` and moving image tags are returned as `unresolved`.

## Data and licenses

CISA KEV, FIRST EPSS, the Node.js security WG, and OSV (OpenSSF Malicious Packages, Apache-2.0; GitHub Advisory Database, CC-BY-4.0). Attribution is in the site footer.

## License

Code: [MIT](LICENSE). Data keeps its source licenses (see above).
