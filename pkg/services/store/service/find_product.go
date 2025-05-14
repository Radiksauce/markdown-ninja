package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) FindProduct(ctx context.Context, db db.Queryer, productID guid.GUID) (product store.Product, err error) {
	product, err = service.repo.FindProductByID(ctx, db, productID)
	return
}
