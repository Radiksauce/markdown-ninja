ALTER TABLE events DROP COLUMN organization_id;

ALTER TABLE pages ADD COLUMN body_markdown TEXT NOT NULL DEFAULT '';
UPDATE pages SET body_markdown = blocks#>> '{0,data,markdown}';
ALTER TABLE pages ALTER COLUMN body_markdown DROP DEFAULT;


ALTER TABLE newsletters ADD COLUMN body_markdown TEXT NOT NULL DEFAULT '';
UPDATE newsletters SET body_markdown = blocks#>> '{0,data,markdown}';
ALTER TABLE newsletters ALTER COLUMN body_markdown DROP DEFAULT;


ALTER TABLE product_pages ADD COLUMN body_markdown TEXT NOT NULL DEFAULT '';
UPDATE product_pages SET body_markdown = blocks#>> '{0,data,markdown}';
ALTER TABLE product_pages ALTER COLUMN body_markdown DROP DEFAULT;
