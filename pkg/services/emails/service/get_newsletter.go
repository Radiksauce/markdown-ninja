package service

import (
	"context"

	"markdown.ninja/pkg/services/emails"
)

func (service *EmailsService) GetNewsletter(ctx context.Context, input emails.GetNewsletterInput) (newsletter emails.Newsletter, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	newsletter, err = service.repo.FindNewsletterByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, newsletter.WebsiteID)
	if err != nil {
		return
	}

	return
}
