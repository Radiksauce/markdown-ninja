package service

import (
	"context"

	"markdown.ninja/pkg/services/emails"
)

// TODO: decrease website's used storage? see also CreateNewsletter and UpdateNewsletter
func (service *EmailsService) DeleteNewsletter(ctx context.Context, input emails.DeleteNewsletterInput) (err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	newsletter, err := service.repo.FindNewsletterByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, newsletter.WebsiteID)
	if err != nil {
		return
	}

	err = service.repo.DeleteNewsletter(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	return
}
