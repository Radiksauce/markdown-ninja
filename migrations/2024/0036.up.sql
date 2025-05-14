DELETE FROM tls_certificates;
ALTER TABLE tls_certificates ADD COLUMN secret_id UUID NOT NULL REFERENCES secrets(id);
ALTER TABLE tls_certificates DROP COLUMN encrypted_data;
