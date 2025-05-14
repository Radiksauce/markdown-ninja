package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) FindWebsitesForOrganization(ctx context.Context, db db.Queryer, organizationID guid.GUID) (websites []websites.Website, err error) {
	websites, err = service.repo.FindWebsitesForOrganization(ctx, db, organizationID)
	return
}
