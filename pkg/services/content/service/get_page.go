package service

import (
	"context"

	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) GetPage(ctx context.Context, input content.GetPageInput) (page content.Page, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	page, err = service.repo.FindPageByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, page.WebsiteID)
	if err != nil {
		return
	}

	page.Tags, err = service.repo.FindTagsForPage(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	return
}
