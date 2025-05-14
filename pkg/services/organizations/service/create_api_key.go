package service

import (
	"context"
	"strings"

	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) CreateApiKey(ctx context.Context, input organizations.CreateApiKeyInput) (apiKey organizations.ApiKeyWithToken, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	_, err = service.CheckUserIsStaff(ctx, service.db, actorID, input.OrganizationID)
	if err != nil {
		return
	}

	name := strings.TrimSpace(input.Name)
	err = service.validateApiKeyName(name)
	if err != nil {
		return
	}

	existingApiKeys, err := service.repo.FindApiKeysForOrganization(ctx, service.db, input.OrganizationID)
	if err != nil {
		return
	}
	if len(existingApiKeys) >= 20 {
		err = errs.InvalidArgument("API Keys limit reached. Please conatct support if you need more.")
		return
	}

	apiKey, err = service.generateApiKey(input.OrganizationID, name)
	if err != nil {
		return
	}

	err = service.repo.CreateApiKey(ctx, service.db, apiKey.ApiKey)
	if err != nil {
		return
	}

	return
}
