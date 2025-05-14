package service

import (
	"context"

	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/queue"
	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) TaskDeleteOldUnverifiedContacts(ctx context.Context) (err error) {
	logger := slogx.FromCtx(ctx)

	job := queue.NewJobInput{
		Data: contacts.JobDeleteOldUnverifiedContacts{},
	}
	err = service.queue.Push(ctx, nil, job)
	if err != nil {
		errMessage := "contacts.TaskDeleteOldUnverifiedContacts: Pushing job to queue"
		logger.Error(errMessage, slogx.Err(err))
		err = errs.Internal(errMessage, err)
		return
	}

	return
}
