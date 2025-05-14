package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindLastPublishedPost(ctx context.Context, db db.Queryer, websiteID guid.GUID) (page content.Page, err error) {
	page, err = service.repo.FindLastPublishedPostForWebsite(ctx, db, websiteID)
	return
}
