ALTER TABLE tls_certificates ADD COLUMN IF NOT EXISTS encrypted_value BYTEA NOT NULL DEFAULT '';
ALTER TABLE tls_certificates ALTER COLUMN encrypted_value DROP DEFAULT;
ALTER TABLE tls_certificates DROP CONSTRAINT IF EXISTS tls_certificates_data_secret_id_fkey;
