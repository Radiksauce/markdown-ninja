package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) ListMyProducts(ctx context.Context, input kernel.EmptyInput) (ret kernel.PaginatedResult[site.Product], err error) {
	contact := service.contactsService.CurrentContact(ctx)
	if contact == nil {
		err = kernel.ErrAuthenticationRequired
		return ret, err
	}

	website, err := service.websitesService.FindWebsiteByID(ctx, service.db, contact.WebsiteID)
	if err != nil {
		return
	}

	products, err := service.storeService.FindProductsForContact(ctx, service.db, contact.ID)
	if err != nil {
		return ret, err
	}

	ret.Data = service.convertProducts(website, products)
	return ret, nil
}
