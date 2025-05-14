package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) ListOrganizations(ctx context.Context, input organizations.ListOrganizationsInput) (ret kernel.PaginatedResult[organizations.Organization], err error) {
	httpCtx := httpctx.FromCtx(ctx)

	_, err = service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	if !httpCtx.AccessToken.IsAdmin {
		service.kernel.SleepAuth()
		err = kernel.ErrPermissionDenied
		return
	}

	ret.Data, err = service.repo.FindAllOrganizations(ctx, service.db)
	return
}
