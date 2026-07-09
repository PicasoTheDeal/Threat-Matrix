PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  token TEXT
);

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

CREATE TABLE IF NOT EXISTS headline_comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);