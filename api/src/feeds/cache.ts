import type { Env } from "../env";
import { sha256Hex } from "../crypto";
import { SOURCES, fetchEpss, type EpssScores, type SourceDef } from "./sources";
import type { FeedItem, Link, Pulse, SourceStatus } from "./types";

const FEED_KEY = "feed";
const EPSS_KEY = "epss";
const LOCK_KEY = "lock";
// total source cost handled per refresh run
const REFRESH_BUDGET = 5;
// a failed source is not retried sooner than this
const RETRY_AFTER = 4 * 60;
const EPSS_TTL = 12 * 3600;
// the assembled feed is considered stale after this long without a rebuild
const FEED_STALE_AFTER = 20 * 60;
// how long an isolate serves its in memory copy before re reading d1
const MEMORY_TTL_MS = 60_000;
const LIMITS = { vuln: 160, news: 60, ransomware: 40 } as const;

interface CacheRow {
  key: string;
  payload: string;
  fetched_at: number;
  attempted_at: number;
  ok: number;
}

interface FeedSnapshot {
  body: string;
  etag: string;
  builtAt: number;
  pending: number;
  loadedAt: number;
}

let memory: FeedSnapshot | null = null;

const nowSeconds = () => Math.floor(Date.now() / 1000);

function parse<T>(text: string | undefined, fallback: T): T {
  if (!text) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

async function readRows(db: D1Database, withPayload: boolean): Promise<Map<string, CacheRow>> {
  const columns = withPayload ? "key, payload, fetched_at, attempted_at, ok" : "key, '' AS payload, fetched_at, attempted_at, ok";
  const { results } = await db.prepare(`SELECT ${columns} FROM feed_cache`).all<CacheRow>();
  return new Map(results.map((row) => [row.key, row]));
}

function saveRow(db: D1Database, key: string, payload: string, fetchedAt: number): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO feed_cache (key, payload, fetched_at, attempted_at, ok, error) VALUES (?1, ?2, ?3, ?3, 1, NULL)
       ON CONFLICT(key) DO UPDATE SET payload = ?2, fetched_at = ?3, attempted_at = ?3, ok = 1, error = NULL`,
    )
    .bind(key, payload, fetchedAt);
}

function saveFailure(db: D1Database, key: string, at: number, error: string): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO feed_cache (key, payload, fetched_at, attempted_at, ok, error) VALUES (?1, '', 0, ?2, 0, ?3)
       ON CONFLICT(key) DO UPDATE SET attempted_at = ?2, ok = 0, error = ?3`,
    )
    .bind(key, at, error.slice(0, 200));
}

// sources due for a fetch stalest first limited by the cpu budget
export function pickDue(rows: Map<string, Pick<CacheRow, "fetched_at" | "attempted_at">>, now: number, budget: number): SourceDef[] {
  const due = SOURCES.map((source, order) => {
    const row = rows.get(`src:${source.key}`);
    const fetchedAt = row?.fetched_at ?? 0;
    const attemptedAt = row?.attempted_at ?? 0;
    const isDue = now - fetchedAt >= source.ttl && now - attemptedAt >= RETRY_AFTER;
    return { source, order, overdue: (now - fetchedAt) / source.ttl, never: fetchedAt === 0, isDue };
  })
    .filter((entry) => entry.isDue)
    .sort((a, b) => Number(b.never) - Number(a.never) || (a.never ? a.order - b.order : b.overdue - a.overdue));

  const picked: SourceDef[] = [];
  let spent = 0;
  for (const { source } of due) {
    if (picked.length > 0 && spent + source.cost > budget) continue;
    picked.push(source);
    spent += source.cost;
  }
  return picked;
}

function mergeLinks(a: Link[] = [], b: Link[] = []): Link[] {
  const seen = new Set<string>();
  return [...a, ...b].filter((link) => (seen.has(link.url) ? false : (seen.add(link.url), true))).slice(0, 6);
}

function mergeTags(a: string[] = [], b: string[] = []): string[] {
  const seen = new Set<string>();
  return [...a, ...b].filter((tag) => {
    const key = tag.toLowerCase();
    return seen.has(key) ? false : (seen.add(key), true);
  }).slice(0, 6);
}

// combines records that describe the same cve from several sources into one item
export function mergeItems(groups: FeedItem[][]): FeedItem[] {
  const byId = new Map<string, FeedItem>();
  for (const group of groups) {
    for (const item of group) {
      const existing = byId.get(item.id);
      if (!existing) {
        byId.set(item.id, { ...item });
        continue;
      }
      if (existing.title === existing.id && item.title !== item.id) existing.title = item.title;
      if (!existing.summary) existing.summary = item.summary;
      existing.severity ??= item.severity;
      existing.cvss ??= item.cvss;
      existing.kev ||= item.kev;
      existing.ransomware ||= item.ransomware;
      existing.due ??= item.due;
      existing.sources = [...new Set([...existing.sources, ...item.sources])];
      existing.tags = mergeTags(existing.tags, item.tags);
      existing.links = mergeLinks(existing.links, item.links);
    }
  }
  return [...byId.values()];
}

function latest(items: FeedItem[], keep: number): FeedItem[] {
  return [...items].sort((a, b) => b.date.localeCompare(a.date)).slice(0, keep);
}

async function assemble(db: D1Database, rows: Map<string, CacheRow>, now: number): Promise<FeedSnapshot> {
  const itemsOf = (key: string) => parse<{ items?: FeedItem[] }>(rows.get(`src:${key}`)?.payload, {}).items ?? [];

  // kev first so its plain language name and added date lead on merged records
  const vulns = latest(mergeItems([itemsOf("kev"), itemsOf("nvd"), itemsOf("circl"), itemsOf("ghsa")]), LIMITS.vuln);

  // epss reuse stored scores look up only ids we have not seen or everything once the scores age out
  const epssRow = rows.get(EPSS_KEY);
  let scores = parse<EpssScores>(epssRow?.payload, {});
  const ids = vulns.map((v) => v.id).filter((id) => id.startsWith("CVE-"));
  const expired = !epssRow || now - epssRow.fetched_at >= EPSS_TTL;
  const missing = expired ? ids : ids.filter((id) => !(id in scores));
  const retryOk = !epssRow || now - epssRow.attempted_at >= RETRY_AFTER || expired;
  if (missing.length > 0 && retryOk) {
    try {
      const fresh = await fetchEpss(missing);
      // remember ids with no score yet so they are not requested again on every run
      for (const id of missing) fresh[id] ??= [-1, 0];
      const wanted = new Set(ids);
      scores = Object.fromEntries(Object.entries({ ...scores, ...fresh }).filter(([id]) => wanted.has(id)));
      await saveRow(db, EPSS_KEY, JSON.stringify(scores), expired ? now : epssRow!.fetched_at)
        .run();
    } catch (err) {
      await saveFailure(db, EPSS_KEY, now, String((err as Error)?.message || err)).run();
    }
  }
  for (const vuln of vulns) {
    const score = scores[vuln.id];
    if (score && score[0] >= 0) {
      vuln.epss = score[0];
      vuln.epssPercentile = score[1];
    }
  }

  const items = [...vulns, ...latest(itemsOf("news"), LIMITS.news), ...latest(itemsOf("ransomware"), LIMITS.ransomware)]
    .sort((a, b) => b.date.localeCompare(a.date));
  const pulse = parse<Pulse>(rows.get("src:isc")?.payload, {});

  const sources: SourceStatus[] = SOURCES.map((source) => {
    const row = rows.get(`src:${source.key}`);
    return {
      key: source.key,
      label: source.label,
      ok: !!row && row.ok === 1 && row.fetched_at > 0,
      fetchedAt: row?.fetched_at ?? 0,
      count: source.key === "isc" ? 0 : itemsOf(source.key).length,
    };
  });
  const pending = sources.filter((s) => s.fetchedAt === 0 && !rows.get(`src:${s.key}`)?.attempted_at).length;

  // the version only changes when content does so unchanged feeds answer conditional requests with 304
  const content = JSON.stringify({ items, pulse });
  const version = (await sha256Hex(content)).slice(0, 20);
  const body = `{"version":"${version}","generatedAt":${now},"pending":${pending},"sources":${JSON.stringify(sources)},${content.slice(1)}`;
  await saveRow(db, FEED_KEY, body, now).run();
  return { body, etag: `"${version}"`, builtAt: now, pending, loadedAt: Date.now() };
}

// fetches the sources that are due within the cpu budget stores each result then rebuilds the assembled feed
export async function refreshFeed(env: Env, db: D1Database, budget = REFRESH_BUDGET): Promise<FeedSnapshot> {
  const now = nowSeconds();
  const rows = await readRows(db, true);
  const due = pickDue(rows, now, budget);

  const results = await Promise.allSettled(due.map((source) => source.fetch(env)));
  const writes: D1PreparedStatement[] = [];
  results.forEach((result, index) => {
    const source = due[index];
    const key = `src:${source.key}`;
    const previous = rows.get(key);
    if (result.status === "rejected") {
      const message = String(result.reason?.message || result.reason || "failed");
      console.warn(`feed source ${source.key} failed: ${message}`);
      writes.push(saveFailure(db, key, now, message));
      rows.set(key, { key, payload: previous?.payload ?? "", fetched_at: previous?.fetched_at ?? 0, attempted_at: now, ok: 0 });
      return;
    }
    let payload: string;
    if (Array.isArray(result.value)) {
      const earlier = parse<{ items?: FeedItem[] }>(previous?.payload, {}).items ?? [];
      const seen = new Set(result.value.map((item) => item.id));
      payload = JSON.stringify({ items: latest([...result.value, ...earlier.filter((item) => !seen.has(item.id))], source.keep) });
    } else {
      payload = JSON.stringify(result.value);
    }
    writes.push(saveRow(db, key, payload, now));
    rows.set(key, { key, payload, fetched_at: now, attempted_at: now, ok: 1 });
  });
  if (writes.length > 0) await db.batch(writes);

  memory = await assemble(db, rows, now);
  return memory;
}

// lets one caller through per mingapseconds across all isolates
async function acquireRefreshLock(db: D1Database, minGapSeconds: number): Promise<boolean> {
  const now = nowSeconds();
  const row = await db
    .prepare(
      `INSERT INTO feed_cache (key, payload, fetched_at, attempted_at) VALUES (?1, '', 0, ?2)
       ON CONFLICT(key) DO UPDATE SET attempted_at = ?2 WHERE feed_cache.attempted_at <= ?3
       RETURNING attempted_at`,
    )
    .bind(LOCK_KEY, now, now - minGapSeconds)
    .first();
  return !!row;
}

async function loadSnapshot(db: D1Database): Promise<FeedSnapshot | null> {
  if (memory && Date.now() - memory.loadedAt < MEMORY_TTL_MS) return memory;
  const row = await db
    .prepare("SELECT payload, fetched_at FROM feed_cache WHERE key = ?")
    .bind(FEED_KEY)
    .first<{ payload: string; fetched_at: number }>();
  if (!row || !row.payload) return null;
  const version = row.payload.match(/^\{"version":"([a-f0-9]+)"/)?.[1] ?? String(row.fetched_at);
  const pending = Number(row.payload.slice(0, 120).match(/"pending":(\d+)/)?.[1] ?? 0);
  memory = { body: row.payload, etag: `"${version}"`, builtAt: row.fetched_at, pending, loadedAt: Date.now() };
  return memory;
}

// serves the cached feed and never calls upstream apis on the request path
export async function serveFeed(request: Request, env: Env, db: D1Database, ctx: ExecutionContext): Promise<Response> {
  let snapshot = await loadSnapshot(db);

  if (!snapshot) {
    // very first request after a deploy build once unless another request is already doing it
    if (await acquireRefreshLock(db, 20)) {
      snapshot = await refreshFeed(env, db);
    } else {
      return new Response('{"version":"","generatedAt":0,"pending":1,"sources":[],"items":[],"pulse":{}}', {
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
  } else {
    const age = nowSeconds() - snapshot.builtAt;
    // normally the cron trigger keeps things fresh this covers a missed run or sources still warming up
    const gap = snapshot.pending > 0 ? 15 : 60;
    if ((snapshot.pending > 0 && age >= gap) || age >= FEED_STALE_AFTER) {
      ctx.waitUntil(
        acquireRefreshLock(db, gap)
          .then((ok) => (ok ? refreshFeed(env, db) : undefined))
          .catch((err) => console.warn("background refresh failed", err)),
      );
    }
  }

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    ETag: snapshot.etag,
    "Cache-Control": snapshot.pending > 0 ? "no-cache" : "public, max-age=120, stale-while-revalidate=600",
  };
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch && ifNoneMatch.replace(/^W\//, "") === snapshot.etag) {
    return new Response(null, { status: 304, headers });
  }
  return new Response(snapshot.body, { headers });
}

export async function feedHealth(db: D1Database): Promise<unknown> {
  const { results } = await db
    .prepare("SELECT key, fetched_at, attempted_at, ok, error, length(payload) AS bytes FROM feed_cache ORDER BY key")
    .all();
  return results;
}
