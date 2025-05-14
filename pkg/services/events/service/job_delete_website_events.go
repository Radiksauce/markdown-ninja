package service

import (
	"context"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) JobDeleteWebsiteEvents(ctx context.Context, input events.JobDeleteWebsiteEvents) (err error) {
	err = service.repo.DeleteWebsiteEvents(ctx, service.eventsDb, input.WebsiteID)
	if err != nil {
		return
	}

	return
}
