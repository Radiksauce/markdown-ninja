package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) RemoveStaff(ctx context.Context, input organizations.RemoveStaffInput) (err error) {
	httpCtx := httpctx.FromCtx(ctx)

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	accessToken := httpCtx.AccessToken
	if !accessToken.IsAdmin {
		actorStaff, err := service.CheckUserIsStaff(ctx, service.db, actorID, input.OrganizationID)
		if err != nil {
			return err
		}

		if actorStaff.Role != organizations.StaffRoleAdministrator {
			return kernel.ErrPermissionDenied
		}
	}

	staffToRemove, err := service.repo.FindStaff(ctx, service.db, input.UserID, input.OrganizationID)
	if err != nil {
		return
	}

	staffs, err := service.getStaffsWithDetails(ctx, service.db, input.OrganizationID)
	if err != nil {
		return
	}

	adminsCount := 0
	for _, staff := range staffs {
		if staff.Staff.Role == organizations.StaffRoleAdministrator {
			adminsCount += 1
		}
	}

	if staffToRemove.Role == organizations.StaffRoleAdministrator && adminsCount < 2 {
		err = organizations.ErrCantRemoveLastAdministrator
		return
	}

	err = service.repo.DeleteStaff(ctx, service.db, staffToRemove.UserID, staffToRemove.OrganizationID)
	if err != nil {
		return
	}

	return
}
