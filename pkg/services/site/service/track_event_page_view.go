package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/events"
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) TrackEventPageView(ctx context.Context, input site.TrackEventPageViewInput) (err error) {
	httpCtx := httpctx.FromCtx(ctx)
	hostname := httpCtx.Hostname

	website, err := service.websitesService.FindWebsiteByDomain(ctx, service.db, hostname)
	if err != nil {
		return
	}

	trackEventInput := events.TrackPageViewInput{
		WebsitePrimaryDomain: website.PrimaryDomain,
		Path:                 input.Path,
		IpAddress:            httpCtx.Client.IPStr,
		HeaderReferrer:       input.HeaderReferrer,
		HeaderUserAgent:      httpCtx.Client.UserAgent,
		QueryParameterRef:    input.QueryParameterRef,
		WebsiteID:            website.ID,
	}
	service.eventsService.TrackPageView(ctx, trackEventInput)

	return
}
