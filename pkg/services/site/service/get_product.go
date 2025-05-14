package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/site"
	"markdown.ninja/pkg/services/store"
)

func (service *SiteService) GetProduct(ctx context.Context, input site.GetProductInput) (ret site.Product, err error) {
	contact := service.contactsService.CurrentContact(ctx)
	if contact == nil {
		err = kernel.ErrAuthenticationRequired
		return
	}

	website, err := service.websitesService.FindWebsiteByID(ctx, service.db, contact.WebsiteID)
	if err != nil {
		return
	}

	product, err := service.storeService.FindProductWithContent(ctx, service.db, input.ProductID)
	if err != nil {
		return
	}

	if !product.WebsiteID.Equal(website.ID) {
		err = store.ErrProductNotFound
		return
	}

	ret = service.convertProduct(website, product)

	return ret, nil
}
