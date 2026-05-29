CREATE TABLE IF NOT EXISTS channels(
  channel_id BLOB PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('dm', 'text')),
  name TEXT,
  dm_user_low BLOB,
  dm_user_high BLOB,
  created_at INTEGER NOT NULL,
  CHECK (
    (kind = 'dm' AND name IS NULL
      AND dm_user_low IS NOT NULL AND dm_user_high IS NOT NULL
      AND dm_user_low < dm_user_high)
    OR
    (kind = 'text' AND name IS NOT NULL
      AND dm_user_low IS NULL AND dm_user_high IS NULL)
  ),
  FOREIGN KEY (dm_user_low) REFERENCES users(user_id) ON DELETE CASCADE,
  FOREIGN KEY (dm_user_high) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_dm_pair
  ON channels(dm_user_low, dm_user_high) WHERE kind = 'dm';

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_text_name
  ON channels(name) WHERE kind = 'text';

CREATE TABLE IF NOT EXISTS messages(
  message_id BLOB PRIMARY KEY NOT NULL,
  channel_id BLOB NOT NULL,
  author_id BLOB NOT NULL,
  seq INTEGER NOT NULL,
  content BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (channel_id, seq),
  FOREIGN KEY (channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE,
  FOREIGN KEY (author_id) REFERENCES users(user_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_channel_seq ON messages(channel_id, seq);

ALTER TABLE users ADD COLUMN is_mod INTEGER NOT NULL DEFAULT 0;
