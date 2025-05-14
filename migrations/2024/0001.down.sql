AlTER TABLE users DROP COLUMN totp_secret_id;
AlTER TABLE websites_email_info DROP COLUMN postmark_server_token_secret_id;
AlTER TABLE assets DROP COLUMN website_id;
AlTER TABLE assets DROP COLUMN product_id;

DROP TABLE waiting_list;


DROP TABLE events;

DROP TABLE order_line_items;
DROP TABLE orders;
DROP TABLE contact_product_access;
DROP TABLE coupons_products;
DROP TABLE coupons;
DROP TABLE book_chapters;
DROP TABLE book_versions;
DROP TABLE book_data;
DROP TABLE product_pages;
DROP TABLE products;

DROP TABLE newsletters;
DROP TABLE emails_website_configuration;

DROP TABLE contacts_sessions;
DROP TABLE contacts_labels;
DROP TABLE labels;
DROP TABLE contacts;

DROP TABLE pages;
DROP TABLE redirects;
DROP TABLE domains;
DROP TABLE pages_tags;
DROP TABLE tags;
DROP TABLE websites_staff_invitations;
DROP TABLE snippets;
DROP TABLE api_keys;
DROP TABLE websites_email_info;
DROP TABLE websites_staffs;
DROP TABLE websites;

DROP TABLE users;
DROP TABLE sessions;
DROP TABLE pending_users;

DROP TABLE assets;
DROP TABLE secrets;
DROP TABLE queue;
