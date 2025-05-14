package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindProductAssets(ctx context.Context, db db.Queryer, productID guid.GUID) (assets []content.Asset, err error) {
	assets, err = service.repo.FindProductAssets(ctx, db, productID)
	return
}
