package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindTag(ctx context.Context, db db.Queryer, websiteID guid.GUID, tag string) (ret content.Tag, err error) {
	return service.repo.FindTagByName(ctx, db, websiteID, tag)
}
