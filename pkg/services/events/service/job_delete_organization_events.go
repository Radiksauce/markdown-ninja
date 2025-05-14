package service

import (
	"context"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) JobDeleteOrganizationEvents(ctx context.Context, input events.JobDeleteOrganizationEvents) (err error) {
	err = service.repo.DeleteOrganizationEvents(ctx, service.eventsDb, input.OrganizationID)
	if err != nil {
		return
	}

	return
}
