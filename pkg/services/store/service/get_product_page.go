package service

import (
	"context"

	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) GetProductPage(ctx context.Context, input store.GetProductPageInput) (page store.ProductPage, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	pageToDelete, err := service.repo.FindProductPageByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	product, err := service.repo.FindProductByID(ctx, service.db, pageToDelete.ProductID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, product.WebsiteID)
	if err != nil {
		return
	}

	page, err = service.repo.FindProductPageByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	return
}
