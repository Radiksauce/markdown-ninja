package service

import (
	"context"

	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) DeleteApiKey(ctx context.Context, input organizations.DeleteApiKeyInput) (err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	apiKey, err := service.repo.FindApiKeyByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	_, err = service.CheckUserIsStaff(ctx, service.db, actorID, apiKey.OrganizationID)
	if err != nil {
		return
	}

	err = service.repo.DeleteApiKey(ctx, service.db, apiKey.ID)
	if err != nil {
		return
	}

	return
}
