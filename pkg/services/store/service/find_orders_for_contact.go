package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) FindOrdersForContact(ctx context.Context, db db.Queryer, contactID guid.GUID) (orders []store.Order, err error) {
	orders, err = service.repo.FindOrdersForContact(ctx, db, contactID)
	return
}
