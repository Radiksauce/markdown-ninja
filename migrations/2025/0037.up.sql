DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS pending_users;
ALTER TABLE IF EXISTS secrets DROP COLUMN IF EXISTS user_id;

DELETE FROM staffs;
DELETE FROM staff_invitations;

ALTER TABLE IF EXISTS staffs DROP CONSTRAINT IF EXISTS staffs_user_id_fkey;
ALTER TABLE IF EXISTS staff_invitations DROP CONSTRAINT IF EXISTS staff_invitations_inviter_id_fkey;

DROP TABLE IF EXISTS users;

ALTER TABLE emails_website_configuration ADD COLUMN domain_verified BOOLEAN NOT NULL DEFAULT 'false';
ALTER TABLE emails_website_configuration ALTER COLUMN domain_verified DROP DEFAULT;
UPDATE emails_website_configuration SET domain_verified = (return_path_verified AND dkim_verified);

ALTER TABLE emails_website_configuration ADD COLUMN dns_records JSONB NOT NULL DEFAULT '[]';
ALTER TABLE emails_website_configuration ALTER COLUMN dns_records DROP DEFAULT;
UPDATE emails_website_configuration SET dns_records = json_build_array(
    json_build_object('host', dkim_domain, 'type', 'TXT', 'value', dkim_text_value),
    json_build_object('host', return_path_domain, 'type', 'CNAME', 'value', return_path_cname_value)
);


ALTER TABLE emails_website_configuration ADD COLUMN domain_id TEXT NOT NULL DEFAULT '';
ALTER TABLE emails_website_configuration ALTER COLUMN domain_id DROP DEFAULT;
UPDATE emails_website_configuration SET domain_id = postmark_domain_id;


ALTER TABLE emails_website_configuration ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
ALTER TABLE emails_website_configuration ALTER COLUMN server_id DROP DEFAULT;
UPDATE emails_website_configuration SET server_id = postmark_server_id;




ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS postmark_domain_id;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS postmark_server_id;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS dkim_domain;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS dkim_text_value;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS dkim_verified;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS return_path_domain;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS return_path_cname_value;
ALTER TABLE emails_website_configuration DROP COLUMN IF EXISTS return_path_verified;
