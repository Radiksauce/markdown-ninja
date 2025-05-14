package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/websites"
)

func (service *ContentService) ListSnippets(ctx context.Context, input content.ListSnippetsInput) (ret kernel.PaginatedResult[content.Snippet], err error) {
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

	ret.Data, err = service.repo.FindSnippetsForWebsite(ctx, service.db, input.WebsiteID)
	if err != nil {
		return
	}

	return
}
