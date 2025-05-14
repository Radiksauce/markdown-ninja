SET default_toast_compression=lz4;
ALTER TABLE pages ALTER COLUMN blocks SET COMPRESSION lz4;
