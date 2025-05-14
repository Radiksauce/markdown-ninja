package service

import (
	"context"

	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) VerifyApiKey(ctx context.Context, tokenStr string) (apiKey organizations.ApiKey, err error) {
	parsedApiKey, err := service.parseApiKey(tokenStr)
	if err != nil {
		service.kernel.SleepAuthFailure()
		err = organizations.ErrApiKeyIsNotValid
		return
	}

	apiKey, err = service.repo.FindApiKeyByID(ctx, service.db, parsedApiKey.Id)
	if err != nil {
		if errs.IsNotFound(err) {
			service.kernel.SleepAuthFailure()
			err = organizations.ErrApiKeyIsNotValid
		}
		return
	}

	err = service.verifyApiKey(apiKey, parsedApiKey)
	if err != nil {
		service.kernel.SleepAuthFailure()
		err = organizations.ErrApiKeyIsNotValid
		return
	}

	return
}
