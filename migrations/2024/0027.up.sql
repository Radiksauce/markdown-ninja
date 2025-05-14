ALTER TABLE users ADD COLUMN two_fa_str TEXT;
UPDATE users SET two_fa_str = 'totp' WHERE two_fa = 1;
ALTER TABLE users DROP COLUMN two_fa;
ALTER TABLE users RENAME COLUMN two_fa_str TO two_fa;
