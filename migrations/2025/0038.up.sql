ALTER TABLE emails_website_configuration DROP CONSTRAINT IF EXISTS emails_website_configuration_postmark_server_token_secret__fkey;

DELETE FROM secrets WHERE id = ANY (SELECT postmark_server_token_secret_id FROM emails_website_configuration);

ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS postmark_server_token_secret_id;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS domain_id;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS server_id;
