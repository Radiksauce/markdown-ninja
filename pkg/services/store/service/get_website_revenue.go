package service

import (
	"context"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

func (service *StoreService) GetWebsiteRevenue(ctx context.Context, db db.Queryer, websiteID guid.GUID, from, to time.Time) (revenue int64, err error) {
	revenue, err = service.repo.GetWebsiteRevenue(ctx, db, websiteID, from, to)
	return
}
