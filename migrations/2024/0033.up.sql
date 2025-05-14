ALTER TABLE api_keys RENAME COLUMN hash_sha256 TO hash;
ALTER TABLE sessions RENAME COLUMN hash_sha256 TO hash;

DROP TABLE waiting_list;
DELETE FROM tls_certificates;
