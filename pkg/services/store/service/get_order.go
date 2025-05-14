package service

import (
	"context"

	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) GetOrder(ctx context.Context, input store.GetOrderInput) (order store.Order, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	order, err = service.repo.FindOrderByID(ctx, service.db, input.ID, false)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, order.WebsiteID)
	if err != nil {
		return
	}

	order.LineItems, err = service.repo.FindOrderLineItems(ctx, service.db, order.ID)
	if err != nil {
		return
	}

	order.Refunds, err = service.repo.FindRefundsByOrderID(ctx, service.db, order.ID)
	if err != nil {
		return
	}

	return
}
