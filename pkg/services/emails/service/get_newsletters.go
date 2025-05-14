package service

import (
	"context"

	"markdown.ninja/pkg/services/emails"
)

func (service *EmailsService) GetNewsletters(ctx context.Context, input emails.GetNewslettersInput) (ret []emails.NewsletterMetadata, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	newsletters, err := service.repo.FindNewslettersByWebsiteID(ctx, service.db, input.WebsiteID)
	if err != nil {
		return
	}

	ret = convertNewsletterMetadata(newsletters)

	return
}
