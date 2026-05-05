-- Add migration script here
CREATE TABLE IF NOT EXISTS sessions(
  session_id BLOB PRIMARY KEY NOT NULL,
  user_id BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);
