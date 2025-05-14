ALTER TABLE domains DROP COLUMN IF EXISTS cdn_domain_id;


DROP INDEX IF EXISTS index_pages_tags_on_tag_id;
DROP INDEX IF EXISTS index_pages_tags_on_page_id;

CREATE UNIQUE INDEX index_pages_tags_on_page_id_and_tag_id ON pages_tags (page_id, tag_id);
ALTER TABLE pages_tags
    ADD CONSTRAINT index_pages_tags_on_page_id_and_tag_id
    UNIQUE USING INDEX index_pages_tags_on_page_id_and_tag_id;



DROP INDEX IF EXISTS index_tags_on_website_id;
DROP INDEX IF EXISTS index_tags_on_name;

CREATE UNIQUE INDEX index_tags_on_website_id_and_name ON tags (website_id, name);
ALTER TABLE tags
    ADD CONSTRAINT index_tags_on_website_id_and_name
    UNIQUE USING INDEX index_tags_on_website_id_and_name;

ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_website_id_name_key;


----------------------------------------------------------------------------------------------------

-- ALTER TABLE pages_tags ADD COLUMN website_id UUID;

-- UPDATE pages_tags SET website_id = tags.website_id
--     FROM (SELECT * FROM tags) AS tags
--     WHERE pages_tags.tag_id = tags.id;

-- ALTER TABLE pages_tags ALTER COLUMN website_id SET NOT NULL;


-- ALTER TABLE pages_tags ADD COLUMN tag TEXT;

-- UPDATE pages_tags SET tag = tags.name
--     FROM (SELECT * FROM tags) AS tags
--     WHERE pages_tags.tag_id = tags.id;

-- ALTER TABLE pages_tags ALTER COLUMN tag SET NOT NULL;


-- ALTER TABLE pages_tags
--     ADD CONSTRAINT pages_tags_website_id_and_tag_fkey
--     FOREIGN KEY (website_id, tag) REFERENCES tags(website_id, name) ON DELETE CASCADE;

-- DROP INDEX IF EXISTS index_pages_tags_on_page_id;
-- -- CREATE INDEX index_pages_tags_on_website_id_and_page_id ON pages_tags (website_id, page_id);
-- DROP INDEX IF EXISTS index_pages_tags_on_tag_id;
-- CREATE INDEX index_pages_tags_on_page_id_and_tag ON pages_tags (page_id, tag);

-- ALTER TABLE pages_tags DROP COLUMN IF EXISTS tag_id;


-- DROP INDEX IF EXISTS tags_name_website_id_key;
-- CREATE UNIQUE INDEX index_tags_on_website_id_and_name ON tags (website_id, name);
-- DROP INDEX IF EXISTS index_tags_on_name;
-- DROP INDEX IF EXISTS index_tags_on_website_id;


-- ALTER TABLE tags
--   DROP CONSTRAINT tags_pkey,
--   ADD CONSTRAINT tags_pkey
--   PRIMARY KEY (website_id, name);

-- ALTER TABLE tags DROP COLUMN id;
