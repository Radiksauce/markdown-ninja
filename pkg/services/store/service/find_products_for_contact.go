package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) FindProductsForContact(ctx context.Context, db db.Queryer, contactID guid.GUID) (products []store.Product, err error) {
	products, err = service.repo.FindProductsForContact(ctx, db, contactID)
	return
}
