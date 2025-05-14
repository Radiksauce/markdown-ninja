ALTER TABLE websites ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD';
ALTER TABLE websites ALTER COLUMN currency DROP DEFAULT;

ALTER TABLE organizations ADD COLUMN plan TEXT NOT NULL DEFAULT 'unlimited';
ALTER TABLE organizations ALTER COLUMN plan DROP DEFAULT;
CREATE INDEX index_organizations_on_plan ON organizations (plan);


DROP TABLE IF EXISTS staff_invitations;
DROP TABLE IF EXISTS staffs_invitations;

CREATE TABLE staff_invitations (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

  role BIGINT NOT NULL,
  invitee_email TEXT NOT NULL,

  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  inviter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX index_staff_invitations_on_organization_id ON staff_invitations (organization_id);
CREATE UNIQUE INDEX index_staff_invitations_on_organization_id_and_invitee_email ON staff_invitations (organization_id, invitee_email);


ALTER TABLE staffs DROP COLUMN id;
CREATE UNIQUE INDEX index_staffs_on_organization_id_and_user_id ON staffs (organization_id, user_id);
DROP INDEX index_staffs_on_organization_id;
DROP INDEX index_staffs_on_user_id;
