package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindPageByID(ctx context.Context, db db.Queryer, pageID guid.GUID) (page content.Page, err error) {
	page, err = service.repo.FindPageByID(ctx, service.db, pageID)
	if err != nil {
		return
	}

	return
}
