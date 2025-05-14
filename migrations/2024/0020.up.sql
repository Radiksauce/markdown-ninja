ALTER TABLE assets DROP COLUMN hash_blake3;
ALTER TABLE pages DROP COLUMN hash_blake3;
ALTER TABLE newsletters DROP COLUMN hash_blake3;
ALTER TABLE product_pages DROP COLUMN hash_blake3;
ALTER TABLE api_keys RENAME COLUMN hash_blake3 TO hash_sha256;
ALTER TABLE snippets DROP COLUMN hash_blake3;
ALTER TABLE sessions RENAME COLUMN hash_blake3 TO hash_sha256;
