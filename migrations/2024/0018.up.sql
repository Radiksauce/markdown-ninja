DROP INDEX index_events_on_type;
CREATE INDEX index_events_on_website_id_and_type_and_time ON events (website_id, type, time DESC);

ANALYZE events;
