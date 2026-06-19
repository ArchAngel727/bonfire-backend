-- Banned users — entries here cannot log in. Mods and admin can add entries.
-- Only admin can remove them.
CREATE TABLE IF NOT EXISTS banned_users (
  user_id   BLOB    PRIMARY KEY NOT NULL,
  banned_at INTEGER NOT NULL,
  banned_by BLOB    NOT NULL,
  reason    TEXT
);
