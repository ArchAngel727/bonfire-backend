-- Long-term identity bundle per user. Public halves only — private keys
-- live in each client's Tauri data dir and never leave the device.
CREATE TABLE IF NOT EXISTS key_bundles (
  user_id                 BLOB    PRIMARY KEY NOT NULL,
  identity_key            BLOB    NOT NULL,  -- 32 bytes Curve25519
  signing_key             BLOB    NOT NULL,  -- 32 bytes Ed25519
  signed_prekey           BLOB    NOT NULL,  -- 32 bytes
  signed_prekey_signature BLOB    NOT NULL,  -- 64 bytes Ed25519 over signed_prekey
  signed_prekey_id        INTEGER NOT NULL,
  uploaded_at             INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Pool of one-time prekeys per user. Each row is consumed on fetch_bundle
-- via DELETE inside a transaction so two concurrent fetchers can't receive
-- the same prekey.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  user_id    BLOB    NOT NULL,
  prekey_id  INTEGER NOT NULL,
  public_key BLOB    NOT NULL,  -- 32 bytes
  PRIMARY KEY (user_id, prekey_id),
  FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Index used by the consume query.
CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_user
  ON one_time_prekeys (user_id);
