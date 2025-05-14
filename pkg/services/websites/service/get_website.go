package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) GetWebsite(ctx context.Context, input websites.GetWebsiteInput) (website websites.Website, err error) {
	httpCtx := httpctx.FromCtx(ctx)

	if httpCtx.ApiKey != nil {
		website, err = service.repo.FindWebsiteByID(ctx, service.db, input.ID, false)
		if err != nil {
			return websites.Website{}, err
		}

		_, err = service.organizationsService.CheckCurrentApiKey(ctx, website.OrganizationID)
		if err != nil {
			return websites.Website{}, err
		}
	} else {
		actorID, err := service.kernel.CurrentUserID(ctx)
		if err != nil {
			return websites.Website{}, err
		}

		website, err = service.repo.FindWebsiteByID(ctx, service.db, input.ID, false)
		if err != nil {
			return websites.Website{}, err
		}

		if !httpCtx.AccessToken.IsAdmin {
			_, err = service.organizationsService.CheckUserIsStaff(ctx, service.db, actorID, website.OrganizationID)
			if err != nil {
				return websites.Website{}, err
			}
		}
	}

	if input.Domains {
		website.Domains, err = service.repo.FindDomainsForWebsite(ctx, service.db, website.ID)
		if err != nil {
			return website, err
		}
	}

	if input.Redirects {
		website.Redirects, err = service.repo.FindRedirectsForWebsite(ctx, service.db, website.ID)
		if err != nil {
			return website, err
		}
	}

	now := time.Now().UTC()
	firstDayOfTheMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	revenue, err := service.storeService.GetWebsiteRevenue(ctx, service.db, website.ID, firstDayOfTheMonth, now)
	if err != nil {
		return website, err
	}
	website.Revenue = &revenue

	subscribersCount, err := service.contactsService.GetVerifiedAndSubscribedToNewsletterContactsCount(ctx, service.db, website.ID)
	if err != nil {
		return website, err
	}
	website.Subscribers = &subscribersCount

	return website, nil
}
