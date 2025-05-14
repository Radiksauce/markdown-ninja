DELETE FROM settings WHERE key = 'events.analytics_salt';

ALTER TABLE websites ADD COLUMN powered_by BOOLEAN NOT NULL DEFAULT 'true';
ALTER TABLE websites ALTER COLUMN powered_by DROP DEFAULT;
