-- #################################################################################################
-- Utils
-- #################################################################################################

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE queue (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  scheduled_for TIMESTAMP WITH TIME ZONE NOT NULL,
  failed_attempts BIGINT NOT NULL,
  status BIGINT NOT NULL,
  TYPE TEXT NOT NULL,
  data JSONB NOT NULL,
  retry_max BIGINT NOT NULL,
  retry_delay BIGINT NOT NULL,
  retry_strategy BIGINT NOT NULL,
  timeout BIGINT NOT NULL
);
CREATE INDEX index_queue_on_scheduled_for ON queue (scheduled_for);
CREATE INDEX index_queue_on_status ON queue (status);
CREATE INDEX index_queue_on_type ON queue (type);
CREATE INDEX index_queue_on_failed_attempts ON queue (failed_attempts);


CREATE TABLE secrets (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  wrapped_key BYTEA NOT NULL,
  encrypted_data BYTEA NOT NULL
);


-- #################################################################################################
-- Kernel
-- #################################################################################################

CREATE TABLE pending_users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  hashed_password BYTEA NOT NULL,
  failed_attempts BIGINT NOT NULL
);


CREATE TABLE users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  email TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL,
  two_fa BIGINT NOT NULL,
  hashed_password BYTEA NOT NULL,
  blocked_at TIMESTAMP WITH TIME ZONE,
  blocked_reason TEXT NOT NULL,

  totp_secret_id UUID REFERENCES secrets(id)
);
CREATE UNIQUE INDEX index_kernel_users_on_email ON users (email);


CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  secret_hash BYTEA NOT NULL,
  failed_login_attempts BIGINT NOT NULL,
  verified BOOLEAN NOT NULL,
  country_code TEXT NOT NULL,

  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX index_sessions_on_user_id ON sessions (user_id);
CREATE INDEX index_sessions_on_verified ON sessions (verified);
CREATE INDEX index_sessions_on_created_at ON sessions (created_at);



-- #################################################################################################
-- Websites
-- #################################################################################################

CREATE TABLE websites (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  modified_at TIMESTAMP WITH TIME ZONE NOT NULL,
  blocked_at TIMESTAMP WITH TIME ZONE,
  blocked_reason TEXT NOT NULL,

  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  header TEXT NOT NULL,
  footer TEXT NOT NULL,
  navigation JSON NOT NULL,
  language TEXT NOT NULL,
  primary_domain TEXT NOT NULL,
  description_markdown TEXT NOT NULL,
  description_html TEXT NOT NULL,
  description_text TEXT NOT NULL
);
CREATE UNIQUE INDEX index_websites_on_slug ON websites (slug);


CREATE TABLE websites_staffs (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  role BIGINT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE INDEX index_websites_staffs_on_website_id ON websites_staffs (website_id);
CREATE INDEX index_websites_staffs_on_user_id ON websites_staffs (user_id);


CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  secret_hash BYTEA NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,

  UNIQUE (name, website_id)
);
CREATE INDEX index_api_keys_on_website_id ON api_keys (website_id);


CREATE TABLE websites_staff_invitations (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  role INT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  invitee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  inviter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX index_websites_staff_invitations_on_site_id ON websites_staff_invitations (website_id);
CREATE INDEX index_websites_staff_invitations_on_invitee_id ON websites_staff_invitations (invitee_id);


CREATE TABLE redirects (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  pattern TEXT NOT NULL,
  domain TEXT NOT NULL,
  path_pattern TEXT NOT NULL,
  to_url TEXT NOT NULL,
  status BIGINT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_redirects_on_website_id ON redirects (website_id);


CREATE TABLE domains (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  hostname TEXT NOT NULL,
  tls_active BOOLEAN NOT NULL,
  cdn_domain_id TEXT,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX index_domains_on_hostname ON domains (hostname);
CREATE INDEX index_domains_on_website_id ON domains (website_id);
-- CREATE INDEX index_domains_on_tls_cert_updated_at ON domains (tls_cert_updated_at);

-- #################################################################################################
-- Content
-- #################################################################################################

CREATE TABLE pages (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  date TIMESTAMP WITH TIME ZONE NOT NULL,
  type INT NOT NULL,
  title TEXT NOT NULL,
  path TEXT NOT NULL,
  content_markdown TEXT NOT NULL,
  content_html TEXT NOT NULL,
  description TEXT NOT NULL,
  language TEXT NOT NULL,
  size BIGINT NOT NULL,
  sha256 BYTEA NOT NULL,
  draft BOOLEAN NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_pages_on_path ON pages (path);
CREATE INDEX index_pages_on_type ON pages (type);
CREATE INDEX index_pages_on_website_id ON pages (website_id);
CREATE INDEX index_pages_on_date ON pages (date);
CREATE INDEX index_pages_on_draft ON pages (draft);


CREATE TABLE tags (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  description TEXT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,

  UNIQUE (name, website_id)
);
CREATE INDEX index_tags_on_website_id ON tags (website_id);
CREATE INDEX index_tags_on_name ON tags (name);


CREATE TABLE pages_tags (
  page_id UUID NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
  tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE
);
CREATE INDEX index_pages_tags_on_page_id ON pages_tags (page_id);
CREATE INDEX index_pages_tags_on_tag_id ON pages_tags (tag_id);


CREATE TABLE snippets (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  content TEXT NOT NULL,
  sha256 BYTEA NOT NULL,
  render_in_emails BOOLEAN NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_snippets_on_website_id ON snippets (website_id);
CREATE INDEX index_snippets_on_name ON snippets (name);



CREATE TABLE assets (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  type BIGINT NOT NULL,
  name TEXT NOT NULL,
  folder TEXT NOT NULL,
  media_type TEXT NOT NULL,
  size BIGINT NOT NULL,
  sha256 BYTEA NOT NULL,

  is_book_asset BOOLEAN NOT NULL,

  video_id TEXT NOT NULL,
  video_status BIGINT NOT NULL,
  video_duration BIGINT NOT NULL
);
CREATE INDEX index_assets_on_folder ON assets (folder);
CREATE INDEX index_assets_on_name ON assets (name);
CREATE INDEX index_assets_on_type ON assets (type);
CREATE INDEX index_assets_on_video_status ON assets (video_status) WHERE type = 4;


-- #################################################################################################
-- Contacts
-- #################################################################################################

CREATE TABLE contacts (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subscribed_to_newsletter_at TIMESTAMP WITH TIME ZONE,
  subscribed_to_product_updates_at TIMESTAMP WITH TIME ZONE,
  verified BOOLEAN NOT NULL,
  country_code TEXT NOT NULL,
  failed_signup_attempts BIGINT NOT NULL,
  signup_code_hash TEXT NOT NULL,
  verify_email_signature BYTEA NOT NULL,

  billing_address JSONB NOT NULL,
  stripe_customer_id TEXT,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,

  UNIQUE (email, website_id)
);
CREATE INDEX index_contacts_on_website_id ON contacts (website_id);
CREATE INDEX index_contacts_on_email ON contacts (email);
CREATE INDEX index_contacts_on_verified ON contacts (verified);
CREATE INDEX index_contacts_on_subscribed_to_newsletter_at ON contacts (subscribed_to_newsletter_at);
CREATE INDEX index_contacts_on_created_at ON contacts (created_at);


CREATE TABLE contacts_sessions (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  secret_hash BYTEA NOT NULL,
  code_hash TEXT NOT NULL,
  failed_login_attempts BIGINT NOT NULL,
  verified BOOLEAN NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
  contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX index_contacts_sessions_on_website_id ON contacts_sessions (website_id);
CREATE INDEX index_contacts_sessions_on_contact_id ON contacts_sessions (contact_id);
CREATE INDEX index_contacts_sessions_on_verified ON contacts_sessions (verified);
CREATE INDEX index_contacts_sessions_on_created_at ON contacts_sessions (created_at);


CREATE TABLE labels (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  description TEXT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,

  UNIQUE (name, website_id)
);
CREATE INDEX index_labels_on_website_id ON labels (website_id);
CREATE INDEX index_labels_on_name ON labels (name);


CREATE TABLE contacts_labels (
  contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
  label_id UUID NOT NULL REFERENCES labels(id) ON DELETE CASCADE
);
CREATE INDEX index_contacts_labels_on_contact_id ON contacts_labels (contact_id);
CREATE INDEX index_contacts_labels_on_label_id ON contacts_labels (label_id);


-- #################################################################################################
-- Emails
-- #################################################################################################

CREATE TABLE emails_website_configuration (
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  from_name TEXT NOT NULL,
  from_address TEXT NOT NULL,
  from_domain TEXT NOT NULL,
  postmark_domain_id TEXT NOT NULL,
  postmark_server_id TEXT NOT NULL,
  dkim_verified BOOLEAN NOT NULL,
  return_path_verified BOOLEAN NOT NULL,
  dkim_domain TEXT NOT NULL,
  dkim_text_value TEXT NOT NULL,
  return_path_domain TEXT NOT NULL,
  return_path_cname_value TEXT NOT NULL,

  postmark_server_token_secret_id UUID NOT NULL REFERENCES secrets(id),
  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX index_emails_website_configuration_on_website_id ON emails_website_configuration (website_id);
-- CREATE UNIQUE INDEX index_emails_website_configuration_on_from_domain ON emails_website_configuration (from_domain);


CREATE TABLE newsletters (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  subject TEXT NOT NULL,
  content_markdown TEXT NOT NULL,
  size BIGINT NOT NULL,
  sha256 BYTEA NOT NULL,
  sent_at TIMESTAMP WITH TIME ZONE,
  scheduled_for TIMESTAMP WITH TIME ZONE,
  last_test_sent_at TIMESTAMP WITH TIME ZONE,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_newsletters_on_website_id ON newsletters (website_id);
CREATE INDEX index_newsletters_on_scheduled_for ON newsletters (scheduled_for);
CREATE INDEX index_newsletters_on_sent_at ON newsletters (sent_at);


-- #################################################################################################
-- Products
-- #################################################################################################

CREATE TABLE products (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL,
  description TEXT NOT NULL,
  type BIGINT NOT NULL,
  status BIGINT NOT NULL,
  price BIGINT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_products_on_website_id ON products (website_id);


CREATE TABLE book_data (
  author TEXT NOT NULL,
  subtitle TEXT NOT NULL,
  cover TEXT NOT NULL,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX index_book_data_on_product_id ON book_data (product_id);


CREATE TABLE book_versions (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  status BIGINT NOT NULL,
  version TEXT NOT NULL,
  notes TEXT NOT NULL,

  pdf_asset_id UUID REFERENCES assets(id),
  epub_asset_id UUID REFERENCES assets(id),
  azw3_asset_id UUID REFERENCES assets(id),

  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX index_book_versions_on_product_id ON book_versions (product_id);


CREATE TABLE book_chapters (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  position BIGINT NOT NULL,
  title TEXT NOT NULL,
  content_markdown TEXT NOT NULL,
  size BIGINT NOT NULL,
  sha256 BYTEA NOT NULL,
  unnumbered BOOLEAN NOT NULL,

  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX index_book_chapters_on_product_id ON book_chapters (product_id);


CREATE TABLE product_pages (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  position BIGINT NOT NULL,
  title TEXT NOT NULL,
  content_markdown TEXT NOT NULL,
  content_html TEXT NOT NULL,
  size BIGINT NOT NULL,
  sha256 BYTEA NOT NULL,

  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX index_product_pages_on_product_id ON product_pages (product_id);


CREATE TABLE coupons (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  code TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE,
  discount BIGINT NOT NULL,
  uses_limit BIGINT NOT NULL,
  archived_at TIMESTAMP WITH TIME ZONE,
  description TEXT NOT NULL,

  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,

  UNIQUE(website_id, code)
);
CREATE INDEX index_coupons_on_website_id ON coupons (website_id);
CREATE INDEX index_coupons_on_code ON coupons (code);


CREATE TABLE coupons_products (
  coupon_id UUID NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE INDEX index_coupons_products_on_coupon_id ON coupons_products (coupon_id);
CREATE INDEX index_coupons_products_on_product_id ON coupons_products (product_id);


CREATE TABLE contact_product_access (
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX index_contact_product_access_on_contact_id_and_product_id ON contact_product_access (contact_id, product_id);
-- CREATE INDEX index_contact_product_access_on_contact_id ON contact_product_access (contact_id);
-- CREATE INDEX index_contact_product_access_on_product_id ON contact_product_access (product_id);


CREATE TABLE orders (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  total_amount BIGINT NOT NULL,
  currency TEXT NOT NULL,
  notes TEXT NOT NULL,
  status BIGINT NOT NULL,
  completed_at TIMESTAMP WITH TIME ZONE,
  canceled_at TIMESTAMP WITH TIME ZONE,
  email TEXT NOT NULL,
  billing_address JSONB NOT NULL,

  stripe_checkout_session_id TEXT NOT NULL,
  stripe_payment_intent_id TEXT,
  stripe_invoice_id TEXT,
  stripe_invoice_url TEXT,

  contact_id UUID NOT NULL REFERENCES contacts(id),
  website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE
);
CREATE INDEX index_orders_on_contact_id ON orders (contact_id);
CREATE INDEX index_orders_on_website_id ON orders (website_id);
CREATE INDEX index_orders_on_status ON orders (status);


CREATE TABLE order_line_items (
  product_name TEXT NOT NULL,
  original_product_price BIGINT NOT NULL,
  quantity BIGINT NOT NULL,

  order_id UUID NOT NULL REFERENCES orders(id),
  product_id UUID NOT NULL REFERENCES products(id)
);
CREATE INDEX index_order_line_items_on_order_id ON order_line_items (order_id);
CREATE INDEX index_order_line_items_on_product_id ON order_line_items (product_id);


-- #################################################################################################
-- Misc
-- #################################################################################################

ALTER TABLE secrets
  ADD COLUMN website_id UUID REFERENCES websites(id) ON DELETE CASCADE,
  ADD COLUMN user_id UUID REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE assets
  ADD COLUMN website_id UUID NOT NULL REFERENCES websites(id),
  ADD COLUMN product_id UUID REFERENCES products(id);
CREATE INDEX index_assets_on_website_id ON assets (website_id);
CREATE INDEX index_assets_on_product_id ON assets (product_id);
CREATE INDEX index_assets_on_is_book_asset ON assets (is_book_asset) WHERE product_id IS NOT NULL;



CREATE TABLE waiting_list (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  email TEXT NOT NULL
);


-- #################################################################################################
-- Events
-- #################################################################################################

CREATE TABLE events (
  time TIMESTAMP WITH TIME ZONE NOT NULL,

  -- name TEXT,
  type BIGINT NOT NULL,
  data JSONB NOT NULL,
  -- referrer TEXT NOT NULL,
  -- page TEXT NOT NULL,
  -- country_code TEXT NOT NULL,
  -- browser INT NOT NULL,
  -- os INT NOT NULL,

  website_id UUID NOT NULL,
  anonymous_id UUID,
  contact_id UUID,
  order_id UUID,
  newsletter_id UUID
);
CREATE INDEX index_events_on_website_id ON events (website_id);
CREATE INDEX index_events_on_type ON events (type);
CREATE INDEX index_events_on_contact_id ON events (contact_id) WHERE contact_id IS NOT NULL;
CREATE INDEX index_events_on_anonymous_id ON events (anonymous_id) WHERE anonymous_id IS NOT NULL;
CREATE INDEX index_events_on_order_id ON events (order_id) WHERE order_id IS NOT NULL;
-- CREATE INDEX index_events_on_contact_id ON events USING BTREE (((data->>'contact_id')::UUID));
-- CREATE INDEX index_events_on_anonymous_id ON events USING BTREE (((data->>'anonymous_id')::UUID)) WHERE (data->>'anonymous_id')::UUID IS NOT NULL;

SELECT create_hypertable('events', 'time', if_not_exists => TRUE);
