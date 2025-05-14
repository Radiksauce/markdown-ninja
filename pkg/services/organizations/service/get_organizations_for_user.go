package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) GetOrganizationsForUser(ctx context.Context, input organizations.GetOrganizationsForUserInput) (orgs []organizations.Organization, err error) {
	httpCtx := httpctx.FromCtx(ctx)

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	userID := actorID
	if input.UserID != nil {
		userID = *input.UserID
		if !httpCtx.AccessToken.IsAdmin && !userID.Equal(actorID) {
			err = kernel.ErrPermissionDenied
			return
		}
	}

	orgs, err = service.repo.FindOrganizationsForUser(ctx, service.db, userID)
	return orgs, err
}
