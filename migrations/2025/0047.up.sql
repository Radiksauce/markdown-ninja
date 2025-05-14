CREATE TABLE IF NOT EXISTS jwt_keys (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    algorithm TEXT NOT NULL,
    encrypted_secret_key BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS index_jwt_keys_on_created_at ON jwt_keys (created_at DESC);

DELETE FROM contacts_sessions;
