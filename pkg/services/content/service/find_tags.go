package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindTags(ctx context.Context, db db.Queryer, websiteID guid.GUID) (tags []content.Tag, err error) {
	tags, err = service.repo.FindTagsForWebsite(ctx, db, websiteID)
	return
}
