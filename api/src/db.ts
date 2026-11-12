const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     username TEXT UNIQUE NOT NULL,
     password_hash TEXT NOT NULL,
     salt TEXT NOT NULL,
     token TEXT
   )`,
  `CREATE TABLE IF NOT EXISTS sessions (
     token_hash TEXT PRIMARY KEY,
     user_id INTEGER NOT NULL REFERENCES users(id),
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL
   )`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)`,
  `CREATE TABLE IF NOT EXISTS user_parameters (
     user_id INTEGER PRIMARY KEY REFERENCES users(id),
     tags TEXT NOT NULL DEFAULT '[]'
   )`,
  `CREATE TABLE IF NOT EXISTS headline_likes (
     user_id INTEGER NOT NULL,
     log_id TEXT NOT NULL,
     PRIMARY KEY (user_id, log_id),
     FOREIGN KEY (user_id) REFERENCES users(id)
   )`,
  `CREATE INDEX IF NOT EXISTS idx_likes_log ON headline_likes (log_id)`,
  `CREATE TABLE IF NOT EXISTS headline_comments (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     log_id TEXT NOT NULL,
     user_id INTEGER NOT NULL,
     content TEXT NOT NULL,
     created_at TEXT DEFAULT (datetime('now')),
     FOREIGN KEY (user_id) REFERENCES users(id)
   )`,
  `CREATE INDEX IF NOT EXISTS idx_comments_log ON headline_comments (log_id)`,
  `CREATE TABLE IF NOT EXISTS feed_cache (
     key TEXT PRIMARY KEY,
     payload TEXT NOT NULL,
     fetched_at INTEGER NOT NULL,
     attempted_at INTEGER NOT NULL DEFAULT 0,
     ok INTEGER NOT NULL DEFAULT 1,
     error TEXT
   )`,
  `CREATE TABLE IF NOT EXISTS rate_limits (
     key TEXT PRIMARY KEY,
     count INTEGER NOT NULL,
     window_start INTEGER NOT NULL
   )`,
  // old sessions were permanent tokens stored in plain text
  `UPDATE users SET token = NULL WHERE token IS NOT NULL`,
];

let ready: Promise<void> | null = null;

// creates missing tables
export function ensureSchema(db: D1Database): Promise<void> {
  if (!ready) {
    ready = db
      .batch(SCHEMA.map((sql) => db.prepare(sql)))
      .then(() => undefined)
      .catch((err) => {
        ready = null;
        throw err;
      });
  }
  return ready;
}

export async function cleanup(db: D1Database): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    db.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 86400),
  ]);
}
