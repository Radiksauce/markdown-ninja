ALTER TABLE events ADD COLUMN organization_id UUID;

UPDATE events SET organization_id = websites.organization_id
  FROM websites
  WHERE events.website_id = websites.id;

ALTER TABLE events ALTER COLUMN organization_id SET NOT NULL;
CREATE INDEX index_events_on_organization_id ON events (organization_id);
