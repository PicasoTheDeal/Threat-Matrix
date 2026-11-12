-- threat matrix database schema cloudflare d1 sqlite
-- the worker creates anything missing on start up so running this by hand is optional
-- the npm script db migrate runs it

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  -- new rows hold a pbkdf2 hash and older rows hold a bare sha 256 digest
  -- older rows keep their salt in the next column and are upgraded at the next sign in
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  -- unused since v2 sessions table
  token TEXT
);

-- only the sha 256 of a session token is stored
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS user_parameters (
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  tags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS headline_likes (
  user_id INTEGER NOT NULL,
  log_id TEXT NOT NULL,
  PRIMARY KEY (user_id, log_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_likes_log ON headline_likes (log_id);

CREATE TABLE IF NOT EXISTS headline_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_comments_log ON headline_comments (log_id);

-- one row per upstream source src nvd plus the assembled feed and epss scores
CREATE TABLE IF NOT EXISTS feed_cache (
  key TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  attempted_at INTEGER NOT NULL DEFAULT 0,
  ok INTEGER NOT NULL DEFAULT 1,
  error TEXT
);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
