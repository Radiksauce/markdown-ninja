package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) ListMyOrders(ctx context.Context, input kernel.EmptyInput) (ret kernel.PaginatedResult[site.Order], err error) {
	contact := service.contactsService.CurrentContact(ctx)
	if contact == nil {
		err = kernel.ErrAuthenticationRequired
		return
	}

	orders, err := service.storeService.FindCompletedOrdersForContact(ctx, service.db, contact.ID)
	if err != nil {
		return
	}

	ret.Data = service.convertOrders(orders)

	return
}
