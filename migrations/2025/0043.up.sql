ALTER TABLE organizations ADD COLUMN extra_slots BIGINT NOT NULL DEFAULT 0;
ALTER TABLE organizations ALTER COLUMN extra_slots DROP DEFAULT;

UPDATE organizations SET plan = 'enterprise' WHERE plan = 'unlimited';
UPDATE organizations SET plan = 'pro' WHERE plan = 'hobby';

ALTER TABLE organizations DROP COLUMN extra_staffs;
ALTER TABLE organizations DROP COLUMN extra_websites;
ALTER TABLE organizations DROP COLUMN extra_storage;
