DROP TABLE contacts_labels;
DROP TABLE labels;


DROP TABLE api_keys;

CREATE TABLE api_keys (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE,

  name TEXT NOT NULL,
  hash_sha256 BYTEA NOT NULL,

  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  UNIQUE (name, organization_id)
);
CREATE INDEX index_api_keys_on_organization_id ON api_keys (organization_id);
