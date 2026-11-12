import type { Env } from "./env";
import { getUser, requireUser, verifyTurnstile, type User } from "./auth";
import { HttpError, clientIp, json, readJsonBody } from "./http";
import { rateLimit } from "./ratelimit";

const LOG_ID_RE = /^[A-Za-z0-9._:-]{3,80}$/;
const COMMENT_MAX = 1000;
const LINK_RE = /(https?:\/\/|www\.)/i;

interface CommentRow {
  id: number;
  content: string;
  created_at: string;
  user_id: number;
  username: string;
}

function readLogId(value: unknown): string {
  if (typeof value !== "string" || !LOG_ID_RE.test(value)) throw new HttpError(400, "Unknown item.");
  return value;
}

function readComment(value: unknown): string {
  const content = typeof value === "string" ? value.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").trim() : "";
  if (!content) throw new HttpError(400, "Write something first.");
  if (content.length > COMMENT_MAX) throw new HttpError(400, `Comments can be up to ${COMMENT_MAX} characters.`);
  if (LINK_RE.test(content)) throw new HttpError(400, "Links are not allowed in comments.");
  return content;
}

// likes like state and comments for one item in a single batched round trip
async function snapshot(db: D1Database, logId: string, user: User | null) {
  const [likes, mine, comments] = await db.batch([
    db.prepare("SELECT COUNT(*) AS cnt FROM headline_likes WHERE log_id = ?").bind(logId),
    db.prepare("SELECT 1 AS x FROM headline_likes WHERE log_id = ? AND user_id = ?").bind(logId, user?.id ?? -1),
    db
      .prepare(
        `SELECT hc.id, hc.content, hc.created_at, hc.user_id, u.username
         FROM headline_comments hc JOIN users u ON hc.user_id = u.id
         WHERE hc.log_id = ? ORDER BY hc.id ASC LIMIT 200`,
      )
      .bind(logId),
  ]);
  return {
    likes: Number((likes.results[0] as { cnt?: number } | undefined)?.cnt ?? 0),
    liked: mine.results.length > 0,
    comments: (comments.results as unknown as CommentRow[]).map((c) => ({
      id: c.id,
      content: c.content,
      created_at: c.created_at,
      username: c.username,
      mine: !!user && c.user_id === user.id,
    })),
  };
}

// counts for every item that has any activity
export async function summary(request: Request, db: D1Database): Promise<Response> {
  const user = await getUser(db, request);
  const [likes, comments, mine] = await db.batch([
    db.prepare("SELECT log_id, COUNT(*) AS cnt FROM headline_likes GROUP BY log_id LIMIT 5000"),
    db.prepare("SELECT log_id, COUNT(*) AS cnt FROM headline_comments GROUP BY log_id LIMIT 5000"),
    db.prepare("SELECT log_id FROM headline_likes WHERE user_id = ? LIMIT 5000").bind(user?.id ?? -1),
  ]);
  const counts: Record<string, [number, number]> = {};
  for (const row of likes.results as { log_id: string; cnt: number }[]) counts[row.log_id] = [row.cnt, 0];
  for (const row of comments.results as { log_id: string; cnt: number }[]) {
    counts[row.log_id] = [counts[row.log_id]?.[0] ?? 0, row.cnt];
  }
  return json({ counts, liked: (mine.results as { log_id: string }[]).map((r) => r.log_id) });
}

export async function detail(request: Request, db: D1Database): Promise<Response> {
  const logId = readLogId(new URL(request.url).searchParams.get("id"));
  return json(await snapshot(db, logId, await getUser(db, request)));
}

export async function interact(request: Request, env: Env, db: D1Database): Promise<Response> {
  const user = await requireUser(db, request);
  await rateLimit(db, "interact", String(user.id), 120, 60);
  const body = await readJsonBody(request);
  const logId = readLogId(body.log_id);
  const commentId = Number(body.comment_id);

  switch (body.action) {
    case "like":
      await db.prepare("INSERT OR IGNORE INTO headline_likes (user_id, log_id) VALUES (?, ?)").bind(user.id, logId).run();
      break;
    case "unlike":
      await db.prepare("DELETE FROM headline_likes WHERE user_id = ? AND log_id = ?").bind(user.id, logId).run();
      break;
    case "comment": {
      const content = readComment(body.content);
      await rateLimit(db, "comment", String(user.id), 10, 600);
      await verifyTurnstile(env, body.turnstileToken, clientIp(request));
      await db
        .prepare("INSERT INTO headline_comments (log_id, user_id, content) VALUES (?, ?, ?)")
        .bind(logId, user.id, content)
        .run();
      break;
    }
    case "edit_comment": {
      if (!Number.isInteger(commentId)) throw new HttpError(400, "Unknown comment.");
      const content = readComment(body.content);
      const result = await db
        .prepare("UPDATE headline_comments SET content = ? WHERE id = ? AND user_id = ? AND log_id = ?")
        .bind(content, commentId, user.id, logId)
        .run();
      if (!result.meta.changes) throw new HttpError(403, "You can only edit your own comments.");
      break;
    }
    case "delete_comment": {
      if (!Number.isInteger(commentId)) throw new HttpError(400, "Unknown comment.");
      const result = await db
        .prepare("DELETE FROM headline_comments WHERE id = ? AND user_id = ? AND log_id = ?")
        .bind(commentId, user.id, logId)
        .run();
      if (!result.meta.changes) throw new HttpError(403, "You can only delete your own comments.");
      break;
    }
    default:
      throw new HttpError(400, "Unknown action.");
  }
  return json({ success: true, interaction: await snapshot(db, logId, user) });
}
