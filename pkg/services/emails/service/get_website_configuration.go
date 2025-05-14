package service

import (
	"context"

	"markdown.ninja/pkg/services/emails"
)

func (service *EmailsService) GetWebsiteConfiguration(ctx context.Context, input emails.GetWebsiteConfigurationInput) (configuration emails.WebsiteConfiguration, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	configuration, err = service.repo.FindWebsiteConfiguration(ctx, service.db, input.WebsiteID)
	if err != nil {
		return
	}

	return
}
