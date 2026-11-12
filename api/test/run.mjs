// end to end tests for the worker npm test
import assert from "node:assert/strict";
import { build } from "esbuild";
import { createD1 } from "./d1-shim.mjs";
import { fixtures, rss } from "./fixtures.mjs";

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const outDir = mkdtempSync(join(tmpdir(), "threat-matrix-test-"));
process.on("exit", () => rmSync(outDir, { recursive: true, force: true }));
await build({ entryPoints: ["src/index.ts"], bundle: true, format: "esm", outfile: join(outDir, "worker.mjs"), platform: "neutral", target: "es2022", logLevel: "silent" });
const worker = (await import(pathToFileURL(join(outDir, "worker.mjs")).href)).default;
console.warn = () => {};

const upstreamCalls = [];
let upstreamDown = false;
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = String(input);
  upstreamCalls.push(url);
  if (url.includes("challenges.cloudflare.com")) {
    const token = init.body.get("response");
    return Response.json({ success: token === "good-token" });
  }
  if (upstreamDown) return new Response("down", { status: 503 });
  for (const [needle, xml] of Object.entries(rss)) if (url.includes(needle)) return new Response(xml);
  for (const [needle, data] of Object.entries(fixtures)) if (url.includes(needle)) return Response.json(data);
  return new Response("not found", { status: 404 });
};

const env = { DB: createD1(), TURNSTILE_SECRET_KEY: "secret", ALLOWED_ORIGINS: "https://app.example, https://other.example" };
const ORIGIN = "https://app.example";
const pendingWork = [];
const ctx = { waitUntil: (p) => pendingWork.push(p), passThroughOnException() {} };
const settle = async () => { while (pendingWork.length) await pendingWork.shift(); };
const runCron = async (times) => { for (let i = 0; i < times; i++) { await worker.scheduled({}, env, ctx); await settle(); } };

async function call(method, path, { body, token, origin = ORIGIN, headers = {}, ip = "203.0.113.5" } = {}) {
  const h = { "CF-Connecting-IP": ip, ...headers };
  if (origin) h.Origin = origin;
  if (token) h.Cookie = `other=1; tm_session=${token}`;
  if (body !== undefined && !h["Content-Type"]) h["Content-Type"] = "application/json";
  const res = await worker.fetch(new Request(`https://api.example.workers.dev${path}`, { method, headers: h, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) }), env, ctx);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  // the session token only ever travels in the cookie so tests read it from there
  const cookie = res.headers.get("Set-Cookie") || "";
  const issued = cookie.match(/tm_session=([a-f0-9]{64})/)?.[1];
  if (issued && data && typeof data === "object") data.token = issued;
  return { status: res.status, headers: res.headers, data };
}

let passed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (err) {
    console.log(`FAIL  ${name}\n      ${err.message}`);
    process.exitCode = 1;
  }
}

// feed
let feed;
await test("feed builds over several runs within the CPU budget", async () => {
  const first = await call("GET", "/api/feed");
  assert.equal(first.status, 200);
  assert.ok(first.data.pending > 0, "first build should be partial");
  await runCron(2);
  feed = (await call("GET", "/api/feed")).data;
});

await test("memory cache is refreshed after a rebuild", async () => {
  assert.equal(feed.pending, 0);
  assert.ok(feed.sources.every((s) => s.ok), JSON.stringify(feed.sources));
});

const byId = () => Object.fromEntries(feed.items.map((i) => [i.id, i]));

await test("same CVE from KEV, NVD, CIRCL and GitHub merges into one item", async () => {
  const items = byId();
  const acme = items["CVE-2026-1111"];
  assert.equal(feed.items.filter((i) => i.id === "CVE-2026-1111").length, 1);
  assert.deepEqual(acme.sources, ["CISA KEV", "NVD"]);
  assert.equal(acme.title, "Acme Gateway Command Injection Vulnerability");
  assert.equal(acme.kev, true);
  assert.equal(acme.ransomware, true);
  assert.equal(acme.cvss, 9.8, "primary CVSS metric wins");
  assert.equal(acme.severity, "critical");
  assert.equal(acme.epss, 0.94231);
  assert.ok(acme.summary.includes('(CWE-78)') && acme.summary.includes('"KB-12" <advisory>'), "text is no longer mangled");
  const foo = items["CVE-2026-2222"];
  assert.deepEqual(foo.sources, ["NVD", "CIRCL", "GitHub"]);
  assert.equal(foo.title, "Foo CMS draft disclosure");
  assert.equal(foo.severity, "medium");
  assert.ok(foo.tags.includes("foo-cms") && foo.tags.includes("Foo CMS") && !foo.tags.includes("n/a"));
  assert.equal(foo.epss, undefined);
});

await test("rejected CVEs and unknown record formats are dropped", async () => {
  const items = byId();
  assert.equal(items["CVE-2026-3333"], undefined);
  assert.equal(items["CVE-2026-4444"], undefined);
});

await test("KEV is sorted by date added, GHSA-only advisories are kept", async () => {
  const items = byId();
  assert.ok(feed.items.findIndex((i) => i.id === "CVE-2026-1111") < feed.items.findIndex((i) => i.id === "CVE-2020-0001"));
  assert.equal(items["GHSA-zzzz-9999-yyyy"].severity, "high");
  assert.equal(items["GHSA-zzzz-9999-yyyy"].summary, "Prototype pollution in merge().");
});

await test("RSS and Atom parse; unsafe links and undated items are skipped", async () => {
  const news = feed.items.filter((i) => i.kind === "news");
  assert.equal(news.length, 2);
  const thn = news.find((n) => n.sources[0] === "The Hacker News");
  assert.equal(thn.title, 'New "Botnet" Hits Routers & Cameras');
  assert.equal(thn.summary, "Researchers found a botnet — details here.");
  assert.ok(!thn.summary.includes("<") && !thn.summary.includes("alert"));
  const krebs = news.find((n) => n.sources[0] === "Krebs on Security");
  assert.equal(krebs.url, "https://krebsonsecurity.com/2026/11/post/");
  assert.equal(krebs.title, "Atom entry title");
});

await test("ransomware entries never link to leak sites", async () => {
  const rw = feed.items.filter((i) => i.kind === "ransomware");
  assert.equal(rw.length, 2);
  assert.ok(rw.every((r) => new URL(r.url).hostname === "www.ransomware.live"));
  assert.ok(!JSON.stringify(feed).includes(".onion"));
  assert.ok(rw.find((r) => r.title === "Legacy Shape Ltd").url.endsWith("/group/akira"));
});

await test("SANS ISC pulse is included", async () => {
  assert.equal(feed.pulse.infocon, "green");
  assert.deepEqual(feed.pulse.ports[0], { port: 23, records: 91234 });
});

await test("feed requests are served from cache: no upstream calls, ETag gives 304", async () => {
  upstreamCalls.length = 0;
  const a = await call("GET", "/api/feed");
  const etag = a.headers.get("ETag");
  assert.ok(etag && a.headers.get("Cache-Control").includes("max-age=120"));
  const b = await call("GET", "/api/feed", { headers: { "If-None-Match": etag } });
  assert.equal(b.status, 304);
  assert.equal(upstreamCalls.length, 0);
});

await test("when every upstream is down the previous data is kept", async () => {
  upstreamDown = true;
  env.DB.raw.exec("UPDATE feed_cache SET fetched_at = 1, attempted_at = 0 WHERE key LIKE 'src:%'");
  await runCron(4);
  const after = (await call("GET", "/api/feed")).data;
  assert.equal(after.items.length, feed.items.length);
  assert.ok(after.sources.some((s) => !s.ok));
  upstreamDown = false;
});

// auth
const PASSWORD = "correct horse battery";
let token;

await test("signup validates input and requires Turnstile", async () => {
  assert.equal((await call("POST", "/api/signup", { body: { username: "ab", password: PASSWORD, turnstileToken: "good-token" } })).status, 400);
  assert.equal((await call("POST", "/api/signup", { body: { username: "alice", password: "short", turnstileToken: "good-token" } })).status, 400);
  assert.equal((await call("POST", "/api/signup", { body: { username: "alice", password: "password1234", turnstileToken: "good-token" } })).status, 400);
  assert.equal((await call("POST", "/api/signup", { body: { username: "alice", password: PASSWORD, turnstileToken: "bad" } })).status, 400);
  const ok = await call("POST", "/api/signup", { body: { username: "alice", password: PASSWORD, turnstileToken: "good-token" } });
  assert.equal(ok.status, 201);
  token = ok.data.token;
  assert.match(token, /^[a-f0-9]{64}$/);
  const cookie = ok.headers.get("Set-Cookie");
  assert.ok(cookie.includes("HttpOnly") && cookie.includes("Secure") && cookie.includes("SameSite=Strict") && cookie.includes("Path=/api"));
  assert.ok(!(await worker.fetch(new Request("https://api.example.workers.dev/api/me", { headers: { Authorization: `Bearer ${token}` } }), env, ctx)).ok, "bearer tokens are no longer accepted");
  assert.equal((await call("POST", "/api/signup", { body: { username: "ALICE", password: PASSWORD, turnstileToken: "good-token" }, ip: "203.0.113.6" })).status, 409);
});

await test("passwords use PBKDF2 and session tokens are stored hashed", async () => {
  const user = env.DB.raw.prepare("SELECT * FROM users WHERE username = 'alice'").get();
  assert.match(user.password_hash, /^pbkdf2-sha256\$100000\$[a-f0-9]{32}\$[a-f0-9]{64}$/);
  assert.equal(user.token, null);
  const sessions = env.DB.raw.prepare("SELECT * FROM sessions").all();
  assert.equal(sessions.length, 1);
  assert.notEqual(sessions[0].token_hash, token);
});

await test("login: wrong password rejected, new token per login, logout revokes", async () => {
  assert.equal((await call("POST", "/api/login", { body: { username: "alice", password: "nope nope nope", turnstileToken: "good-token" } })).status, 401);
  assert.equal((await call("POST", "/api/login", { body: { username: "ghost", password: PASSWORD, turnstileToken: "good-token" } })).status, 401);
  const a = await call("POST", "/api/login", { body: { username: "Alice", password: PASSWORD, turnstileToken: "good-token" } });
  assert.equal(a.status, 200);
  assert.notEqual(a.data.token, token);
  assert.equal((await call("GET", "/api/me", { token: a.data.token })).data.username, "alice");
  const out = await call("POST", "/api/logout", { token: a.data.token });
  assert.ok(out.headers.get("Set-Cookie").includes("Max-Age=0"));
  assert.equal((await call("GET", "/api/me", { token: a.data.token })).status, 401);
  assert.equal((await call("GET", "/api/me", { token })).status, 200);
});

await test("expired sessions stop working", async () => {
  const a = await call("POST", "/api/login", { body: { username: "alice", password: PASSWORD, turnstileToken: "good-token" } });
  env.DB.raw.exec(`UPDATE sessions SET expires_at = 1 WHERE token_hash != '${"x"}' AND created_at >= 0 AND rowid = (SELECT max(rowid) FROM sessions)`);
  assert.equal((await call("GET", "/api/me", { token: a.data.token })).status, 401);
});

await test("legacy SHA-256 accounts sign in and are upgraded to PBKDF2", async () => {
  const { createHash } = await import("node:crypto");
  const legacyPassword = "L".repeat(120) + "egacy-Pass-1!";
  const salt = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const hash = createHash("sha256").update(Buffer.concat([salt, Buffer.from(legacyPassword)])).digest("hex");
  env.DB.raw.prepare("INSERT INTO users (username, password_hash, salt, token) VALUES ('olduser', ?, ?, 'plaintext-legacy-token')").run(hash, salt.toString("hex"));
  assert.equal((await call("GET", "/api/me", { token: "plaintext-legacy-token" })).status, 401, "legacy tokens are not accepted");
  const res = await call("POST", "/api/login", { body: { username: "olduser", password: legacyPassword, turnstileToken: "good-token" }, ip: "203.0.113.9" });
  assert.equal(res.status, 200);
  const row = env.DB.raw.prepare("SELECT password_hash, salt FROM users WHERE username = 'olduser'").get();
  assert.ok(row.password_hash.startsWith("pbkdf2-sha256$100000$"));
  assert.equal((await call("POST", "/api/login", { body: { username: "olduser", password: legacyPassword, turnstileToken: "good-token" }, ip: "203.0.113.9" })).status, 200);
});

await test("only the ten newest sessions per user are kept", async () => {
  for (let i = 0; i < 12; i++) {
    env.DB.raw.exec("DELETE FROM rate_limits");
    const res = await call("POST", "/api/login", { body: { username: "olduser", password: "L".repeat(120) + "egacy-Pass-1!", turnstileToken: "good-token" }, ip: `203.0.113.${100 + i}` });
    assert.equal(res.status, 200);
  }
  const count = env.DB.raw.prepare("SELECT COUNT(*) AS n FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = 'olduser'").get().n;
  assert.equal(count, 10);
});

await test("failed human checks do not count toward a username lockout", async () => {
  for (let i = 0; i < 15; i++) await call("POST", "/api/login", { body: { username: "alice", password: "x".repeat(12), turnstileToken: "bad" }, ip: `198.51.100.${i}` });
  const res = await call("POST", "/api/login", { body: { username: "alice", password: PASSWORD, turnstileToken: "good-token" }, ip: "198.51.100.200" });
  assert.equal(res.status, 200);
});

await test("login is rate limited per IP", async () => {
  let last;
  for (let i = 0; i < 12; i++) last = await call("POST", "/api/login", { body: { username: `u${i}xx`, password: PASSWORD, turnstileToken: "good-token" }, ip: "198.51.100.77" });
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get("Retry-After")) > 0);
});

// topics interactions
await test("topics are validated and normalised", async () => {
  const res = await call("POST", "/api/parameters", { token, body: { tags: [" linux ", "Linux", "<script>", 42, "C++", "x".repeat(41)] } });
  assert.deepEqual(res.data.tags, ["LINUX", "C++"]);
  assert.deepEqual((await call("GET", "/api/parameters", { token })).data.tags, ["LINUX", "C++"]);
  assert.equal((await call("POST", "/api/parameters", { token, body: { tags: "nope" } })).status, 400);
  assert.equal((await call("GET", "/api/parameters")).status, 401);
});

let bobToken;
await test("likes, comments and ownership rules", async () => {
  bobToken = (await call("POST", "/api/signup", { body: { username: "bob", password: PASSWORD + "2", turnstileToken: "good-token" }, ip: "203.0.113.20" })).data.token;
  const id = "CVE-2026-1111";
  assert.equal((await call("POST", "/api/interact", { body: { action: "like", log_id: id } })).status, 401);
  assert.equal((await call("POST", "/api/interact", { token, body: { action: "like", log_id: "bad id!" } })).status, 400);
  await call("POST", "/api/interact", { token, body: { action: "like", log_id: id } });
  const liked = await call("POST", "/api/interact", { token, body: { action: "like", log_id: id } });
  assert.equal(liked.data.interaction.likes, 1);

  assert.equal((await call("POST", "/api/interact", { token, body: { action: "comment", log_id: id, content: "hi" } })).status, 400, "comment needs Turnstile");
  assert.equal((await call("POST", "/api/interact", { token, body: { action: "comment", log_id: id, content: "see https://x.io", turnstileToken: "good-token" } })).status, 400);
  assert.equal((await call("POST", "/api/interact", { token, body: { action: "comment", log_id: id, content: "x".repeat(1001), turnstileToken: "good-token" } })).status, 400);
  const posted = await call("POST", "/api/interact", { token, body: { action: "comment", log_id: id, content: "  Patched ours <b>today</b>  ", turnstileToken: "good-token" } });
  const comment = posted.data.interaction.comments[0];
  assert.equal(comment.content, "Patched ours <b>today</b>");
  assert.equal(comment.mine, true);
  assert.equal(comment.user_id, undefined, "user ids are not exposed");

  assert.equal((await call("POST", "/api/interact", { token: bobToken, body: { action: "edit_comment", log_id: id, comment_id: comment.id, content: "hijack" } })).status, 403);
  assert.equal((await call("POST", "/api/interact", { token: bobToken, body: { action: "delete_comment", log_id: id, comment_id: comment.id } })).status, 403);
  assert.equal((await call("POST", "/api/interact", { token, body: { action: "edit_comment", log_id: id, comment_id: comment.id, content: "go to www.evil.example" } })).status, 400, "edits get the same link rule");
  const edited = await call("POST", "/api/interact", { token, body: { action: "edit_comment", log_id: id, comment_id: comment.id, content: "Patched." } });
  assert.equal(edited.data.interaction.comments[0].content, "Patched.");

  const asBob = await call("GET", `/api/comments?id=${id}`, { token: bobToken });
  assert.equal(asBob.data.comments[0].mine, false);
  assert.equal(asBob.data.liked, false);
  const sum = await call("GET", "/api/interactions", { token });
  assert.deepEqual(sum.data.counts[id], [1, 1]);
  assert.deepEqual(sum.data.liked, [id]);
  assert.deepEqual((await call("GET", "/api/interactions")).data.liked, []);
});

// transport
await test("CORS: only configured origins are echoed; unknown origins cannot write", async () => {
  const good = await call("GET", "/api/feed");
  assert.equal(good.headers.get("Access-Control-Allow-Origin"), ORIGIN);
  const listed = await call("GET", "/api/feed", { origin: "https://other.example" });
  assert.equal(listed.headers.get("Access-Control-Allow-Origin"), "https://other.example");
  const same = await call("POST", "/api/logout", { origin: "https://api.example.workers.dev", body: {} });
  assert.equal(same.status, 200, "requests proxied from the sites own origin are accepted");
  const evil = await call("GET", "/api/feed", { origin: "https://evil.example" });
  assert.equal(evil.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal((await call("GET", "/api/feed", { origin: "http://localhost:5173" })).headers.get("Access-Control-Allow-Origin"), null);
  assert.equal((await call("POST", "/api/interact", { origin: "https://evil.example", token, body: { action: "like", log_id: "CVE-2026-1111" } })).status, 403);
  const pre = await call("OPTIONS", "/api/login");
  assert.equal(pre.status, 204);
  assert.ok(pre.headers.get("Access-Control-Allow-Headers").includes("Content-Type"));
});

await test("bodies must be small JSON; errors do not leak internals", async () => {
  assert.equal((await call("POST", "/api/login", { body: "a=b", headers: { "Content-Type": "text/plain" } })).status, 415);
  assert.equal((await call("POST", "/api/login", { body: "{not json" })).status, 400);
  assert.equal((await call("POST", "/api/login", { body: { username: "a", password: "x".repeat(20000) } })).status, 413);
  const stream = new ReadableStream({ start(c) { for (let i = 0; i < 40; i++) c.enqueue(new TextEncoder().encode("x".repeat(1024))); c.close(); } });
  const chunked = await worker.fetch(new Request("https://api.example.workers.dev/api/login", { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN, "CF-Connecting-IP": "203.0.113.77" }, body: stream, duplex: "half" }), env, ctx);
  assert.equal(chunked.status, 413, "a body with no declared length is still capped");
  assert.equal((await call("GET", "/api/nope")).status, 404);
  const res = await call("GET", "/api/feed");
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  const saved = env.DB.prepare;
  const savedError = console.error;
  console.error = () => {};
  env.DB.prepare = () => { throw new Error("SQLITE secret detail"); };
  const boom = await call("GET", "/api/interactions");
  env.DB.prepare = saved;
  console.error = savedError;
  assert.equal(boom.status, 500);
  assert.ok(!JSON.stringify(boom.data).includes("SQLITE"));
});

await test("account deletion needs the password and removes everything", async () => {
  assert.equal((await call("POST", "/api/account/delete", { token: bobToken, body: { password: "wrong wrong wrong" } })).status, 401);
  assert.equal((await call("POST", "/api/account/delete", { token: bobToken, body: { password: PASSWORD + "2" } })).status, 200);
  assert.equal((await call("GET", "/api/me", { token: bobToken })).status, 401);
  assert.equal(env.DB.raw.prepare("SELECT COUNT(*) AS n FROM users WHERE username = 'bob'").get().n, 0);
});

globalThis.fetch = realFetch;
console.log(`\n${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
