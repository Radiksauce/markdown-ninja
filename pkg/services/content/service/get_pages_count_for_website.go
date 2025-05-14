package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

func (service *ContentService) GetPagesCountForWebsite(ctx context.Context, db db.Queryer, websiteID guid.GUID) (count int64, err error) {
	return service.repo.GetPagesCountForWebsite(ctx, db, websiteID)
}
