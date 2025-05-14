ALTER TABLE sessions ADD COLUMN country_code TEXT NOT NULL DEFAULT 'XX';
UPDATE sessions SET country_code = metadata->>'country_code';
ALTER TABLE sessions DROP COLUMN metadata;
ALTER TABLE sessions ALTER COLUMN country_code DROP DEFAULT;
