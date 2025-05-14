CREATE INDEX IF NOT EXISTS index_events_on_website_id ON events (website_id);
CREATE INDEX IF NOT EXISTS index_events_on_type ON events (type);
CREATE INDEX IF NOT EXISTS index_events_on_contact_id ON events (contact_id) WHERE contact_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS index_events_on_anonymous_id ON events (anonymous_id) WHERE anonymous_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS index_events_on_order_id ON events (order_id) WHERE order_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS index_events_on_organization_id ON events (organization_id);
