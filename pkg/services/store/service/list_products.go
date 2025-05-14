package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) ListProducts(ctx context.Context, input store.ListProductsInput) (ret kernel.PaginatedResult[store.Product], err error) {

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	limit := int64(100)
	ret.Data, err = service.repo.FindProductsByWebsiteID(ctx, service.db, input.WebsiteID, limit)
	if err != nil {
		return
	}

	return
}
