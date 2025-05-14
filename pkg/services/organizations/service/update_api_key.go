package service

import (
	"context"
	"strings"
	"time"

	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) UpdateApiKey(ctx context.Context, input organizations.UpdateApiKeyInput) (apiKey organizations.ApiKey, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	apiKey, err = service.repo.FindApiKeyByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	_, err = service.CheckUserIsStaff(ctx, service.db, actorID, apiKey.OrganizationID)
	if err != nil {
		return
	}

	name := strings.TrimSpace(input.Name)
	err = service.validateApiKeyName(name)
	if err != nil {
		return
	}

	apiKey.Name = name
	apiKey.UpdatedAt = time.Now().UTC()
	err = service.repo.UpdateApiKey(ctx, service.db, apiKey)
	if err != nil {
		return
	}

	return
}
