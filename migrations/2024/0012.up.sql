-- Update pages table to use a TEXT field instead of BIGINT for type
ALTER TABLE pages RENAME COLUMN type TO type_old;
ALTER TABLE pages ADD COLUMN type TEXT NOT NULL DEFAULT '';
UPDATE pages SET type = 'page' WHERE type_old = 0;
UPDATE pages SET type = 'post' WHERE type_old = 1;
ALTER TABLE pages ALTER COLUMN type DROP DEFAULT;
ALTER TABLE pages DROP COLUMN type_old;
CREATE INDEX index_pages_on_type ON pages (type);

-- Add the block column
ALTER TABLE pages ADD COLUMN blocks JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE pages ALTER COLUMN blocks DROP DEFAULT;
UPDATE pages set blocks = json_build_array(json_build_object('type', 'markdown', 'name', 'Markdown', 'data', json_build_object('markdown', content_markdown), 'design', json_build_object()));
ALTER TABLE pages DROP COLUMN content_markdown;
ALTER TABLE pages DROP COLUMN content_html;


ALTER TABLE newsletters ADD COLUMN blocks JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE newsletters ALTER COLUMN blocks DROP DEFAULT;
UPDATE newsletters set blocks = json_build_array(json_build_object('type', 'markdown', 'name', 'Markdown', 'data', json_build_object('markdown', content_markdown), 'design', json_build_object()));
ALTER TABLE newsletters DROP COLUMN content_markdown;

ALTER TABLE websites DROP COLUMN theme;

ALTER TABLE product_pages ADD COLUMN blocks JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE product_pages ALTER COLUMN blocks DROP DEFAULT;
UPDATE product_pages set blocks = json_build_array(json_build_object('type', 'markdown', 'name', 'Markdown', 'data', json_build_object('markdown', content_markdown), 'design', json_build_object()));
ALTER TABLE product_pages DROP COLUMN content_markdown;
ALTER TABLE product_pages DROP COLUMN content_html;
