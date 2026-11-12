import { sha256Hex } from "./crypto";
import { HttpError } from "./http";

// fixed window counter stored in d1
export async function rateLimit(
  db: D1Database,
  scope: string,
  subject: string,
  limit: number,
  windowSeconds: number,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const key = `${scope}:${(await sha256Hex(subject)).slice(0, 32)}`;
  const row = await db
    .prepare(
      `INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN rate_limits.window_start <= ?3 THEN 1 ELSE rate_limits.count + 1 END,
         window_start = CASE WHEN rate_limits.window_start <= ?3 THEN ?2 ELSE rate_limits.window_start END
       RETURNING count, window_start`,
    )
    .bind(key, now, now - windowSeconds)
    .first<{ count: number; window_start: number }>();
  if (row && row.count > limit) {
    const retryAfter = Math.max(1, row.window_start + windowSeconds - now);
    throw new HttpError(429, "Too many attempts. Please wait a moment and try again.", {
      "Retry-After": String(retryAfter),
    });
  }
}
