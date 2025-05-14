package service

import (
	"context"

	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/opt"
	"github.com/bloom42/stdx-go/queue"
	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) TaskSyncUnsubscribedContacts(ctx context.Context) {
	logger := slogx.FromCtx(ctx)

	job := queue.NewJobInput{
		Data:    contacts.JobSyncUnsubscribedContacts{},
		Timeout: opt.Ptr(int64(120)),
	}
	err := service.queue.Push(ctx, nil, job)
	if err != nil {
		logger.Error("contacts.TaskDeleteOldUnverifiedSessions: Pushing job to queue", slogx.Err(err))
	}
}
