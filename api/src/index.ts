import type { Env } from "./env";
import { deleteAccount, getParameters, login, logout, me, setParameters, signup } from "./auth";
import { cleanup, ensureSchema } from "./db";
import { feedHealth, refreshFeed, serveFeed } from "./feeds/cache";
import { HttpError, allowedOrigin, json, withStandardHeaders } from "./http";
import { detail, interact, summary } from "./interactions";

type Handler = (request: Request, env: Env, db: D1Database, ctx: ExecutionContext) => Promise<Response>;

const ROUTES: Record<string, Handler> = {
  "GET /api/feed": (request, env, db, ctx) => serveFeed(request, env, db, ctx),
  "GET /api/health": async (_request, _env, db) => json({ ok: true, cache: await feedHealth(db) }),
  "POST /api/signup": (request, env, db) => signup(request, env, db),
  "POST /api/login": (request, env, db) => login(request, env, db),
  "POST /api/logout": (request, _env, db) => logout(request, db),
  "POST /api/account/delete": (request, _env, db) => deleteAccount(request, db),
  "GET /api/me": (request, _env, db) => me(request, db),
  "GET /api/parameters": (request, _env, db) => getParameters(request, db),
  "POST /api/parameters": (request, _env, db) => setParameters(request, db),
  "GET /api/interactions": (request, _env, db) => summary(request, db),
  "GET /api/comments": (request, _env, db) => detail(request, db),
  "POST /api/interact": (request, env, db) => interact(request, env, db),
};

async function handle(request: Request, env: Env, ctx: ExecutionContext, origin: string | null): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null, { status: 204 });

  // a browsersent an origin we do not recognise refuse anything that changes state
  if (request.method !== "GET" && request.headers.get("Origin") && !origin) {
    throw new HttpError(403, "This origin is not allowed.");
  }
  const handler = ROUTES[`${request.method} ${url.pathname.replace(/\/+$/, "")}`];
  if (!handler) throw new HttpError(404, "Not found.");
  if (!env.DB) throw new HttpError(500, "Database is not configured. Check the D1 binding in wrangler.toml.");

  await ensureSchema(env.DB);
  return handler(request, env, env.DB, ctx);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = allowedOrigin(request, env);
    let response: Response;
    try {
      response = await handle(request, env, ctx, origin);
    } catch (err) {
      if (err instanceof HttpError) {
        response = json({ error: err.message }, err.status, err.headers);
      } else {
        // details go to the worker logs never to the client
        console.error("unhandled error", err);
        response = json({ error: "Something went wrong. Please try again." }, 500);
      }
    }
    return withStandardHeaders(response, origin);
  },

  // cron trigger keeps the feed cache warm so visitors never wait on upstream apis
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    if (!env.DB) return;
    const db = env.DB;
    ctx.waitUntil(
      (async () => {
        await ensureSchema(db);
        await refreshFeed(env, db);
        await cleanup(db);
      })().catch((err) => console.error("scheduled refresh failed", err)),
    );
  },
} satisfies ExportedHandler<Env>;
