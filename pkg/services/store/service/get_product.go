package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/store"
	"markdown.ninja/pkg/services/websites"
)

func (service *StoreService) GetProduct(ctx context.Context, input store.GetProductInput) (product store.Product, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err == nil {
		product, err = service.repo.FindProductByID(ctx, service.db, input.ID)
		if err != nil {
			return
		}

		err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, product.WebsiteID)
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

		product, err = service.repo.FindProductByID(ctx, service.db, input.ID)
		if err != nil {
			return
		}

		website, err = service.websitesService.FindWebsiteByID(ctx, service.db, product.WebsiteID)
		if err != nil {
			return
		}

		_, err = service.organizationsService.CheckCurrentApiKey(ctx, website.OrganizationID)
		if err != nil {
			return
		}
	}

	err = service.hydrateProduct(ctx, service.db, &product)
	if err != nil {
		return
	}

	return
}
