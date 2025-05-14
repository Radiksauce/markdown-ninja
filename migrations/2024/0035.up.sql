DELETE FROM sessions;
DELETE FROM contacts_sessions;

ALTER TABLE pages RENAME COLUMN hash_sha256 TO hash;
ALTER TABLE snippets RENAME COLUMN hash_sha256 TO hash;
ALTER TABLE assets RENAME COLUMN hash_sha256 TO hash;
ALTER TABLE product_pages RENAME COLUMN hash_sha256 TO hash;
ALTER TABLE newsletters RENAME COLUMN hash_sha256 TO hash;
