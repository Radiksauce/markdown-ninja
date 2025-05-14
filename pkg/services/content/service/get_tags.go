package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/websites"
)

func (service *ContentService) GetTags(ctx context.Context, input content.GetTagsInput) (tags []content.Tag, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err == nil {
		err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
		if err != nil {
			return
		}

	} else {
		var website websites.Website
		httpCtx := httpctx.FromCtx(ctx)
		if httpCtx.ApiKey == nil {
			err = kernel.ErrPermissionDenied
			return
		}

		website, err = service.websitesService.FindWebsiteByID(ctx, service.db, input.WebsiteID)
		if err != nil {
			return
		}

		_, err = service.organizationsService.CheckCurrentApiKey(ctx, website.OrganizationID)
		if err != nil {
			return
		}
	}

	tags, err = service.repo.FindTagsForWebsite(ctx, service.db, input.WebsiteID)
	if err != nil {
		return
	}

	return
}
