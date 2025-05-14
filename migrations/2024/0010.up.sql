ALTER TABLE websites DROP COLUMN description_markdown;
ALTER TABLE websites DROP COLUMN description_html;
ALTER TABLE websites RENAME COLUMN description_text TO description;
