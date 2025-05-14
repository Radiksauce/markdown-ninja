-- https://gist.github.com/kjmph/5bd772b2c2df145aa645b837da7eca74
create or replace function uuid_generate_v7()
returns uuid
as $$
begin
  -- use random v4 uuid as starting point (which has the same variant we need)
  -- then overlay timestamp
  -- then set version 7 by flipping the 2 and 1 bit in the version 4 string
  return encode(
    set_bit(
      set_bit(
        overlay(uuid_send(gen_random_uuid())
                placing substring(int8send(floor(extract(epoch from clock_timestamp()) * 1000)::bigint) from 3)
                from 1 for 6
        ),
        52, 1
      ),
      53, 1
    ),
    'hex')::uuid;
end
$$
language plpgsql
volatile;


CREATE TABLE organizations (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  name TEXT NOT NULL
);

INSERT INTO organizations (id, created_at, updated_at, name)
    SELECT uuid_generate_v7(), created_at, updated_at, name FROM users;


CREATE TABLE staffs (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  role BIGINT NOT NULL,

  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id)
);
CREATE INDEX index_staffs_on_organization_id ON staffs (organization_id);
CREATE INDEX index_staffs_on_user_id ON staffs (user_id);

-- role = 1 is Administrator
INSERT INTO staffs (id, created_at, updated_at, role, organization_id, user_id)
    SELECT uuid_generate_v7(), users.created_at, users.updated_at, 1, organizations.id, users.id
        FROM users
        INNER JOIN organizations ON organizations.name = users.name;


CREATE TABLE staffs_invitations (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  role INT NOT NULL,

  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invitee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  inviter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX index_staffa_invitations_on_organization_id ON staffs_invitations (organization_id);
CREATE INDEX index_staffa_invitations_on_invitee_id ON staffs_invitations (invitee_id);



ALTER TABLE websites ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;


WITH new_staffs AS (
    SELECT staffs.organization_id AS organization_id, websites_staffs.website_id AS website_id
        FROM staffs
        INNER JOIN websites_staffs ON websites_staffs.user_id = staffs.user_id
)
UPDATE websites SET organization_id = new_staffs.organization_id
  FROM new_staffs
  WHERE id = new_staffs.website_id;

ALTER TABLE websites ALTER COLUMN organization_id SET NOT NULL;

DROP TABLE websites_staffs;
DROP TABLE websites_staff_invitations;
