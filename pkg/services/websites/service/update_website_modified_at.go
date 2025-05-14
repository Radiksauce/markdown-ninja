package service

import (
	"context"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

// TODO: improve?
func (service *WebsitesService) UpdateWebsiteModifiedAt(ctx context.Context, db db.Queryer, websiteID guid.GUID, modifiedAt time.Time) (err error) {
	err = service.repo.UpdateWebsiteModifiedAt(ctx, db, websiteID, modifiedAt)
	if err != nil {
		return
	}

	return
}
