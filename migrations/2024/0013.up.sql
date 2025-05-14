ALTER TABLE pages ADD COLUMN status TEXT NOT NULL DEFAULT '';
UPDATE pages SET status = 'published' WHERE draft = false AND date <= NOW();
UPDATE pages SET status = 'scheduled' WHERE draft = false AND date > NOW();
UPDATE pages SET status = 'draft' WHERE draft = true;
ALTER TABLE pages DROP COLUMN draft;
CREATE INDEX index_pages_on_status ON pages (status);
ALTER TABLE pages ALTER COLUMN status DROP DEFAULT;


ALTER TABLE pages ADD COLUMN send_as_newsletter BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE pages ALTER COLUMN send_as_newsletter DROP DEFAULT;

ALTER TABLE pages ADD COLUMN newsletter_sent_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE newsletters ADD COLUMN post_id UUID;
