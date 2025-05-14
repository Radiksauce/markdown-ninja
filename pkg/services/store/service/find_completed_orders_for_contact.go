package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) FindCompletedOrdersForContact(ctx context.Context, db db.Queryer, contactID guid.GUID) (orders []store.Order, err error) {
	orders, err = service.repo.FindOrdersWithStatusForContact(ctx, db, contactID, store.OrderStatusCompleted)
	return
}
