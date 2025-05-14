package service

import (
	"context"
	"unicode/utf8"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/content"
)

func (service *ContentService) FindPageByPath(ctx context.Context, db db.Queryer, websiteID guid.GUID, path string) (page content.Page, err error) {
	if !utf8.ValidString(path) {
		err = content.ErrPageNotFound
		return
	}

	page, err = service.repo.FindPageByPath(ctx, service.db, websiteID, path)
	if err != nil {
		return
	}

	return
}
