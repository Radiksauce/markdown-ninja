DELETE FROM events WHERE type = 0;
ALTER TABLE events ADD COLUMN path TEXT;
ALTER TABLE events ADD COLUMN country TEXT;
ALTER TABLE events ADD COLUMN referrer TEXT;
ALTER TABLE events ADD COLUMN browser INT;
ALTER TABLE events ADD COLUMN operating_system INT;
