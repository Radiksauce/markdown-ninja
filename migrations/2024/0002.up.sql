DROP TABLE sessions;

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  hash_blake3 BYTEA NOT NULL,
  failed_2fa_attempts BIGINT NOT NULL,
  verified BOOLEAN NOT NULL,
  metadata JSONB NOT NULL,

  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX index_sessions_on_user_id ON sessions (user_id);
CREATE INDEX index_sessions_on_verified ON sessions (verified);
CREATE INDEX index_sessions_on_created_at ON sessions (created_at);


DELETE FROM api_keys;
ALTER TABLE api_keys DROP COLUMN secret_hash;
ALTER TABLE api_keys ADD COLUMN hash_blake3 BYTEA NOT NULL;


ALTER TABLE users ADD COLUMN last_login_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT '2024-01-01';
ALTER TABLE users ALTER COLUMN last_login_time DROP DEFAULT;
