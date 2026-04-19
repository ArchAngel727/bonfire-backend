-- Add migration script here
CREATE TABLE IF NOT EXISTS users(
  user_id BLOB PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  hashed_pw TEXT NOT NULL
);
