<img src="web/public/logo.svg" alt="Threat Matrix logo" width="96">

# Threat-Matrix

**Deployment:** [Threat-Matrix](https://threat-matrix.pages.dev/)

Threat-Matrix is a serverless threat-intelligence feed. It gathers exploited vulnerabilities, new CVEs,
advisories, ransomware activity and security news into one searchable page. Signed-in users can follow
topics, like items and leave comments.

## Project Philosophy & Limitations

This project was built to be completely free, privacy-respecting, and independent. There is zero ad tracking, and it operates without storing sensitive personal data (no emails required). Because the architecture relies on a fully free infrastructure tier to keep the service accessible, it uses a Cloudflare `.pages.dev` domain.

Additionally, while the app aggregates data from major security outlets, some advanced intelligence feeds are restricted by heavy API paywalls. The current sources are selected to provide the best possible free coverage. Future donations to the project will go directly toward upgrading the domain and unlocking premium API feeds to bypass these limitations.

## What it shows

| Source | What it adds | Key needed |
| --- | --- | --- |
| CISA KEV | Vulnerabilities confirmed as exploited, with remediation due dates | No |
| NVD | Newly published CVEs with CVSS severity | No (optional `NVD_API_KEY`) |
| CIRCL Vulnerability-Lookup | CVE records straight from the CVE list, often ahead of NVD | No |
| GitHub Advisories | Reviewed advisories for npm, pip, Go, Maven and other ecosystems | No (optional `GITHUB_TOKEN`) |
| FIRST EPSS | Probability that each CVE will be exploited in the next 30 days | No |
| Security news | The Hacker News, BleepingComputer, Krebs on Security, CISA advisories, SANS ISC diary (RSS) | No |
| ransomware.live | Recent ransomware victim claims | No |
| SANS ISC | Internet threat level and most-probed ports | No |

Records describing the same CVE are merged into a single item that lists every source.

## Architecture

* **`web/`** React + Vite + TypeScript, deployed on Cloudflare Pages. A small Pages Function
  (`web/functions/api/[[path]].ts`) passes every `/api/*` request to the API Worker through a service
  binding, so the site and the API share one origin.
* **`api/`** Cloudflare Worker (TypeScript) with a D1 (SQLite) database.

### Caching

Visitors never wait on upstream APIs.

1. A cron trigger runs the Worker every five minutes. Each run refreshes the sources whose data has
   aged out (20 minutes to 2 hours depending on the source), within a small CPU budget, and stores the
   normalised result per source in D1. A source that fails keeps its previous data.
2. The merged feed is stored as one row. `GET /api/feed` serves it from memory or a single D1 read, with
   an `ETag` and `Cache-Control`, so repeat requests are answered with `304 Not Modified`.
3. The browser paints from its own stored copy at once, skips the network entirely if that copy is
   under two minutes old, and otherwise revalidates in the background.

`GET /api/health` reports when each source was last fetched and any error.

### Security

* Passwords: PBKDF2-SHA256, 100,000 iterations (the Workers limit), per-user salt, constant-time
  comparison. Accounts created under the old single-round SHA-256 scheme are upgraded when the user
  next signs in.
* Sessions: random 256-bit tokens, stored only as SHA-256 hashes, expiring after 30 days, revoked on
  sign-out, at most ten per user. The token travels only in an `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie, so page scripts can never read it and other sites cannot send it.
* Cloudflare Turnstile on sign-up, sign-in and posting comments; rate limits on all of them.
* Strict input validation, small JSON bodies only, generic error messages, CORS limited to known
  origins, security headers on both the API and the site (including a Content-Security-Policy).

## Running locally

```
# API (http://localhost:8787)
cd api
npm install
echo 'TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA' > .dev.vars   # Cloudflare's test secret
npm run dev
npm test          # end-to-end tests with an in-memory database and stubbed upstream APIs

# Web (http://localhost:5173, /api is proxied to the Worker on port 8787)
cd web
cp .env.example .env.local
npm install
npm run dev
```

To run the cron job by hand during development: `curl http://localhost:8787/cdn-cgi/handler/scheduled`.

## Deploying

```
cd api
wrangler secret put TURNSTILE_SECRET_KEY     # once
npm run deploy                               # also registers the cron trigger

cd ../web
npm run build                                # then deploy dist/ to Cloudflare Pages
```

Nothing about your deployment is written into the code. Set these in the Cloudflare dashboard.

**Pages project (the site)**

| Setting | Name | Value |
| --- | --- | --- |
| Variable | `PUBLIC_TURNSTILE_SITE_KEY` | Your Turnstile site key (required) |
| Variable | `PUBLIC_SITE_URL` | Full site address, for link previews (optional) |
| Binding, type Service | `API` | Your API Worker (required) |

The root directory must be `web`, so the `functions/` folder is picked up. Only variables whose names
start with `PUBLIC_` are built into the page.

**Worker (the API)**

| Setting | Name | Value |
| --- | --- | --- |
| Secret | `TURNSTILE_SECRET_KEY` | Your Turnstile secret (required) |
| Binding, type D1 | `DB` | Your database (required) |
| Variable | `ALLOWED_ORIGINS` | Other sites allowed to call the API directly (optional, usually empty) |
| Secret | `NVD_API_KEY`, `GITHUB_TOKEN` | Raise upstream rate limits (optional) |

Database tables are created automatically on first request; `api/schema.sql` documents them.

## API

| Method and path | Purpose |
| --- | --- |
| `GET /api/feed` | The cached, merged feed |
| `GET /api/health` | Cache status per source |
| `POST /api/signup`, `POST /api/login`, `POST /api/logout` | Accounts and sessions |
| `POST /api/account/delete` | Delete the account and its data (password required) |
| `GET /api/me` | Current user and followed topics |
| `GET /api/parameters`, `POST /api/parameters` | Read and save followed topics |
| `GET /api/interactions` | Like and comment counts for all items |
| `GET /api/comments?id=` | Likes and comments for one item |
| `POST /api/interact` | Like, unlike, comment, edit or delete a comment |

## Donation

Contact me on: [Telegram](https://t.me/TetstackPM)
