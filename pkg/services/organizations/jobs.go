package organizations

import "github.com/bloom42/stdx-go/guid"

type JobSendStaffInvitations struct {
	InvitationIDs []guid.GUID `json:"invitation_ids"`
}

func (JobSendStaffInvitations) JobType() string {
	return "organizations.send_staff_invitations"
}

type JobSendUsageData struct {
	OrganizationID guid.GUID `json:"organization_id"`
}

func (JobSendUsageData) JobType() string {
	return "organizations.send_usage_data"
}

type JobDispatchSendUsageData struct {
}

func (JobDispatchSendUsageData) JobType() string {
	return "organizations.dispatch_send_usage_data"
}
