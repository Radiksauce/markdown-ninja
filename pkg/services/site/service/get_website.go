package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) GetWebsite(ctx context.Context, input kernel.EmptyInput) (ret site.Website, err error) {
	httpCtx := httpctx.FromCtx(ctx)
	hostname := httpCtx.Hostname

	website, err := service.websitesService.FindWebsiteByDomain(ctx, service.db, hostname)
	if err != nil {
		return
	}

	ret = service.convertWebsite(website)

	return
}
