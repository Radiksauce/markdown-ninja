CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  value JSONB NOT NULL
);

INSERT INTO settings (key, created_at, updated_at, value) VALUES ('events.analytics_salt', NOW() AT TIME ZONE 'utc', NOW() AT TIME ZONE 'utc', '{"salt": "X0aZBsJDBE/O4Brb4PM8UdEYU6fEL5bjet48rk5fDTs="}');
