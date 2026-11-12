import type { Env } from "./env";
import { burnPasswordCheck, hashPassword, randomToken, sha256Hex, verifyPassword } from "./crypto";
import { HttpError, clientIp, json, readJsonBody } from "./http";
import { rateLimit } from "./ratelimit";

const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
// older sessions beyond this many per user are dropped at sign in
const MAX_SESSIONS_PER_USER = 10;
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;
const PASSWORD_MIN = 12;
const PASSWORD_MAX = 256;
// sign in accepts longer input so accounts made under the old 128 rule keep working
const PASSWORD_MAX_LOGIN = 4096;
const OBVIOUS_PASSWORDS = new Set([
  "123456789012", "1234567890123", "password1234", "passwordpassword", "qwertyuiop12", "qwertyuiopas",
  "111111111111", "000000000000", "letmeinletmein", "iloveyou1234", "adminadmin12", "administrator",
]);

const SESSION_COOKIE = "tm_session";

function isLocal(request: Request): boolean {
  const host = new URL(request.url).hostname;
  return host === "localhost" || host === "127.0.0.1";
}

// the session travels only in a cookie that page scripts cannot read and other sites cannot send
function sessionCookie(request: Request, token: string, maxAge: number): string {
  const secure = isLocal(request) ? "" : " Secure;";
  return `${SESSION_COOKIE}=${token}; Path=/api; HttpOnly;${secure} SameSite=Strict; Max-Age=${maxAge}`;
}

function readSessionToken(request: Request): string | null {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const [name, value] = part.trim().split("=");
    if (name === SESSION_COOKIE && /^[a-f0-9]{64}$/.test(value || "")) return value;
  }
  return null;
}

export interface User {
  id: number;
  username: string;
}

export async function verifyTurnstile(env: Env, token: unknown, ip: string): Promise<void> {
  if (!env.TURNSTILE_SECRET_KEY) throw new HttpError(503, "Human verification is not configured on the server.");
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) {
    throw new HttpError(400, "Please complete the human verification.");
  }
  let ok = false;
  try {
    const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token });
    if (ip !== "unknown") body.set("remoteip", ip);
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
      signal: AbortSignal.timeout(8000),
    });
    const data = (await resp.json()) as { success?: boolean };
    ok = data.success === true;
  } catch {
    throw new HttpError(503, "Human verification is temporarily unavailable. Try again.");
  }
  if (!ok) throw new HttpError(400, "Human verification failed. Please try again.");
}

export async function getUser(db: D1Database, request: Request): Promise<User | null> {
  const token = readSessionToken(request);
  if (!token) return null;
  const row = await db
    .prepare(
      `SELECT u.id AS id, u.username AS username FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?`,
    )
    .bind(await sha256Hex(token), Math.floor(Date.now() / 1000))
    .first<User>();
  return row || null;
}

export async function requireUser(db: D1Database, request: Request): Promise<User> {
  const user = await getUser(db, request);
  if (!user) throw new HttpError(401, "Please sign in again.");
  return user;
}

async function startSession(db: D1Database, userId: number): Promise<{ token: string; expiresAt: number }> {
  const token = randomToken();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL_SECONDS;
  await db.batch([
    db
      .prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .bind(await sha256Hex(token), userId, now, expiresAt),
    db
      .prepare(
        `DELETE FROM sessions WHERE user_id = ?1 AND token_hash NOT IN (
           SELECT token_hash FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC, rowid DESC LIMIT ?2
         )`,
      )
      .bind(userId, MAX_SESSIONS_PER_USER),
  ]);
  return { token, expiresAt };
}

function readCredentials(body: Record<string, unknown>, maxPassword: number): { username: string; password: string } {
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (!username || !password) throw new HttpError(400, "Enter a username and password.");
  if (password.length > maxPassword) throw new HttpError(400, "That password is too long.");
  return { username, password };
}

export async function signup(request: Request, env: Env, db: D1Database): Promise<Response> {
  const ip = clientIp(request);
  await rateLimit(db, "signup", ip, 5, 3600);
  const body = await readJsonBody(request);
  const { username, password } = readCredentials(body, PASSWORD_MAX);

  if (!USERNAME_RE.test(username)) {
    throw new HttpError(400, "Usernames are 3 to 32 characters: letters, numbers, dot, dash or underscore.");
  }
  if (password.length < PASSWORD_MIN) throw new HttpError(400, `Use at least ${PASSWORD_MIN} characters for the password.`);
  if (OBVIOUS_PASSWORDS.has(password.toLowerCase()) || password.toLowerCase() === username.toLowerCase()) {
    throw new HttpError(400, "That password is too easy to guess. Pick another one.");
  }
  await verifyTurnstile(env, body.turnstileToken, ip);

  const existing = await db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
  if (existing) throw new HttpError(409, "That username is taken.");

  const passwordHash = await hashPassword(password);
  let userId: number;
  try {
    const result = await db
      .prepare("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, '')")
      .bind(username, passwordHash)
      .run();
    userId = Number(result.meta.last_row_id);
  } catch {
    throw new HttpError(409, "That username is taken.");
  }
  const session = await startSession(db, userId);
  return json({ expiresAt: session.expiresAt, username }, 201, {
    "Set-Cookie": sessionCookie(request, session.token, SESSION_TTL_SECONDS),
  });
}

export async function login(request: Request, env: Env, db: D1Database): Promise<Response> {
  const ip = clientIp(request);
  await rateLimit(db, "login-ip", ip, 10, 600);
  const body = await readJsonBody(request);
  const { username, password } = readCredentials(body, PASSWORD_MAX_LOGIN);
  await verifyTurnstile(env, body.turnstileToken, ip);
  // counted only after the human check so nobody can lock an account out with cheap requests
  await rateLimit(db, "login-user", username.toLowerCase(), 10, 600);

  const user = await db
    .prepare("SELECT id, username, password_hash, salt FROM users WHERE username = ? COLLATE NOCASE")
    .bind(username)
    .first<{ id: number; username: string; password_hash: string; salt: string }>();

  const invalid = new HttpError(401, "Wrong username or password.");
  if (!user) {
    await burnPasswordCheck(password);
    throw invalid;
  }
  const check = await verifyPassword(password, user.password_hash, user.salt);
  if (!check.valid) throw invalid;

  if (check.needsUpgrade) {
    await db
      .prepare("UPDATE users SET password_hash = ?, salt = '' WHERE id = ?")
      .bind(await hashPassword(password), user.id)
      .run();
  }
  const session = await startSession(db, user.id);
  return json({ expiresAt: session.expiresAt, username: user.username }, 200, {
    "Set-Cookie": sessionCookie(request, session.token, SESSION_TTL_SECONDS),
  });
}

export async function logout(request: Request, db: D1Database): Promise<Response> {
  const token = readSessionToken(request);
  if (token) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  return json({ success: true }, 200, { "Set-Cookie": sessionCookie(request, "", 0) });
}

export async function deleteAccount(request: Request, db: D1Database): Promise<Response> {
  const user = await requireUser(db, request);
  await rateLimit(db, "delete-account", String(user.id), 5, 600);
  const body = await readJsonBody(request);
  const password = typeof body.password === "string" ? body.password : "";
  if (!password || password.length > PASSWORD_MAX_LOGIN) throw new HttpError(400, "Enter your password to confirm.");
  const row = await db
    .prepare("SELECT password_hash, salt FROM users WHERE id = ?")
    .bind(user.id)
    .first<{ password_hash: string; salt: string }>();
  if (!row || !(await verifyPassword(password, row.password_hash, row.salt)).valid) {
    throw new HttpError(401, "Wrong password.");
  }
  await db.batch([
    db.prepare("DELETE FROM headline_likes WHERE user_id = ?").bind(user.id),
    db.prepare("DELETE FROM headline_comments WHERE user_id = ?").bind(user.id),
    db.prepare("DELETE FROM user_parameters WHERE user_id = ?").bind(user.id),
    db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
    db.prepare("DELETE FROM users WHERE id = ?").bind(user.id),
  ]);
  return json({ success: true }, 200, { "Set-Cookie": sessionCookie(request, "", 0) });
}

// followed topics

const TAG_RE = /^[\p{L}\p{N} .+#/_-]{1,40}$/u;
const MAX_TAGS = 60;

export function normalizeTags(input: unknown): string[] {
  if (!Array.isArray(input)) throw new HttpError(400, "Topics must be a list.");
  const seen = new Set<string>();
  for (const raw of input) {
    if (typeof raw !== "string") continue;
    const tag = raw.trim().replace(/\s+/g, " ").toUpperCase();
    if (TAG_RE.test(tag)) seen.add(tag);
    if (seen.size >= MAX_TAGS) break;
  }
  return [...seen];
}

async function readTags(db: D1Database, userId: number): Promise<string[]> {
  const row = await db.prepare("SELECT tags FROM user_parameters WHERE user_id = ?").bind(userId).first<{ tags: string }>();
  if (!row) return [];
  try {
    const parsed: unknown = JSON.parse(row.tags);
    return Array.isArray(parsed) ? parsed.filter((t): t is string => typeof t === "string") : [];
  } catch {
    return [];
  }
}

export async function me(request: Request, db: D1Database): Promise<Response> {
  const user = await requireUser(db, request);
  return json({ username: user.username, tags: await readTags(db, user.id) });
}

export async function getParameters(request: Request, db: D1Database): Promise<Response> {
  const user = await requireUser(db, request);
  return json({ tags: await readTags(db, user.id) });
}

export async function setParameters(request: Request, db: D1Database): Promise<Response> {
  const user = await requireUser(db, request);
  await rateLimit(db, "params", String(user.id), 120, 60);
  const body = await readJsonBody(request);
  const tags = normalizeTags(body.tags);
  await db
    .prepare("INSERT INTO user_parameters (user_id, tags) VALUES (?1, ?2) ON CONFLICT(user_id) DO UPDATE SET tags = ?2")
    .bind(user.id, JSON.stringify(tags))
    .run();
  return json({ success: true, tags });
}
