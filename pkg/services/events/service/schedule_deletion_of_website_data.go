package service

import (
	"context"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"github.com/bloom42/stdx-go/opt"
	"github.com/bloom42/stdx-go/queue"
	"markdown.ninja/pkg/services/events"
)

func (service *Service) ScheduleDeletionOfWebsiteData(ctx context.Context, tx db.Queryer, websiteID guid.GUID) (err error) {
	in10Minutes := time.Now().UTC().Add(10 * time.Minute)

	job := queue.NewJobInput{
		ScheduledFor: &in10Minutes,
		Data: events.JobDeleteWebsiteEvents{
			WebsiteID: websiteID,
		},
		Timeout:    opt.Int64(1200),
		RetryDelay: opt.Int64(3600),
	}
	err = service.queue.Push(ctx, tx, job)
	if err != nil {
		return
	}
	return
}
