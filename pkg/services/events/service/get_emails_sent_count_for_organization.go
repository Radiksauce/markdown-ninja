package service

import (
	"context"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/events"
)

func (service *Service) GetEmailsSentCountForOrganization(ctx context.Context, db db.Queryer, organizationID guid.GUID, from, to time.Time) (count int64, err error) {
	return service.repo.GetEventsTypeCountForOrganization(ctx, db, events.EventTypeEmailSent, organizationID, from, to)
}
