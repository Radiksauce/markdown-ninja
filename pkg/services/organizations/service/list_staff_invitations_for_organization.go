package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) ListStaffInvitationsForOrganization(ctx context.Context, input organizations.ListStaffInvitationsForOrganizationInput) (ret kernel.PaginatedResult[organizations.StaffInvitation], err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	_, err = service.CheckUserIsStaff(ctx, service.db, actorID, input.OrganizationID)
	if err != nil {
		return
	}

	ret.Data, err = service.repo.FindStaffInvitationsForOrganization(ctx, service.db, input.OrganizationID)
	if err != nil {
		return
	}

	return
}
