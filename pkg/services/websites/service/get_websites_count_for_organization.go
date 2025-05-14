package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

func (service *WebsitesService) GetWebsitesCountForOrganization(ctx context.Context, db db.Queryer, organizationID guid.GUID) (websitesCount int64, err error) {
	return service.repo.GetWebsitesCountForOrganization(ctx, db, organizationID)
}
