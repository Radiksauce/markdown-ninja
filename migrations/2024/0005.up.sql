ALTER TABLE pages RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE pages ADD COLUMN hash_blake3 BYTEA;

ALTER TABLE snippets RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE snippets ADD COLUMN hash_blake3 BYTEA;

ALTER TABLE assets RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE assets ADD COLUMN hash_blake3 BYTEA;

ALTER TABLE newsletters RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE newsletters ADD COLUMN hash_blake3 BYTEA;

ALTER TABLE book_chapters RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE book_chapters ADD COLUMN hash_blake3 BYTEA;

ALTER TABLE product_pages RENAME COLUMN sha256 to hash_sha256;
ALTER TABLE product_pages ADD COLUMN hash_blake3 BYTEA;
