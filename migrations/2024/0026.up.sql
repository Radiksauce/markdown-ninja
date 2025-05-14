ALTER TABLE organizations ADD COLUMN billing_information JSONB NOT NULL DEFAULT '{}'::JSONB;
ALTER TABLE organizations ALTER COLUMN billing_information DROP DEFAULT;
ALTER TABLE organizations ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE organizations ADD COLUMN stripe_subscription_id TEXT;

CREATE UNIQUE INDEX index_organizations_on_stripe_customer_id ON organizations (stripe_customer_id);

ALTER TABLE organizations ADD COLUMN extra_staffs BIGINT NOT NULL DEFAULT 0;
ALTER TABLE organizations ALTER COLUMN extra_staffs DROP DEFAULT;

ALTER TABLE organizations ADD COLUMN extra_websites BIGINT NOT NULL DEFAULT 0;
ALTER TABLE organizations ALTER COLUMN extra_websites DROP DEFAULT;

ALTER TABLE organizations ADD COLUMN extra_storage BIGINT NOT NULL DEFAULT 0;
ALTER TABLE organizations ALTER COLUMN extra_storage DROP DEFAULT;

ALTER TABLE organizations ADD COLUMN payment_due_since TIMESTAMP WITH TIME ZONE;
ALTER TABLE organizations ADD COLUMN usage_last_sent_at TIMESTAMP WITH TIME ZONE;

DROP INDEX IF EXISTS index_snippets_on_name;
CREATE UNIQUE INDEX index_snippets_on_name ON snippets (name);

DROP INDEX IF EXISTS index_pages_on_path;
CREATE UNIQUE INDEX index_pages_on_path ON pages (path, website_id);

ALTER TABLE websites ADD COLUMN custom_icon BOOLEAN NOT NULL DEFAULT 'false';
ALTER TABLE websites ALTER COLUMN custom_icon DROP DEFAULT;

ALTER TABLE websites ADD COLUMN custom_icon_hash BYTEA;


ALTER TABLE websites ADD COLUMN colors JSONB NOT NULL DEFAULT '{"background": "#ffffff", "text": "#000000", "accent": "#0ea5e9"}';
ALTER TABLE websites ALTER COLUMN colors DROP DEFAULT;


ALTER TABLE websites ADD COLUMN theme TEXT NOT NULL DEFAULT 'blog';
ALTER TABLE websites ALTER COLUMN theme DROP DEFAULT;

ALTER TABLE websites ADD COLUMN ad TEXT;

ALTER TABLE websites ADD COLUMN announcement TEXT;

ALTER TABLE websites ADD COLUMN logo TEXT;

ALTER TABLE users RENAME COLUMN last_login_time TO last_login_at;
