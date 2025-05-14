package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) SetDomainAsPrimary(ctx context.Context, input websites.SetDomainAsPrimaryInput) (err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	website, err := service.repo.FindWebsiteByID(ctx, service.db, input.WebsiteID, false)
	if err != nil {
		return
	}

	_, err = service.organizationsService.CheckUserIsStaff(ctx, service.db, actorID, website.OrganizationID)
	if err != nil {
		return
	}

	if input.Domain == nil {
		website.PrimaryDomain = service.getSubdomainForSlug(website.Slug)
	} else {
		var domain websites.Domain

		domain, err = service.repo.FindDomainByHostname(ctx, service.db, *input.Domain)
		if err != nil {
			return
		}

		website.PrimaryDomain = domain.Hostname
	}

	now := time.Now().UTC()

	website.UpdatedAt = now
	website.ModifiedAt = now

	err = service.repo.UpdateWebsite(ctx, service.db, website)
	if err != nil {
		return
	}

	return
}
