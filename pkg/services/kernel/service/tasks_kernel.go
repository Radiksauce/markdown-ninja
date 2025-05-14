package service

import (
	"context"

	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/bloom42/stdx-go/opt"
	"github.com/bloom42/stdx-go/queue"
	"markdown.ninja/pkg/services/kernel"
)

func (service *KernelService) TaskRefreshGeoipDatabase(ctx context.Context) {
	logger := slogx.FromCtx(ctx)

	job := queue.NewJobInput{
		Data:    kernel.JobRefreshGeoipDatabase{},
		Timeout: opt.Int64(600),
	}
	err := service.queue.Push(ctx, nil, job)
	if err != nil {
		logger.Error("kernel.TaskRefreshGeoipDatabase: error pushing job to queue", slogx.Err(err))
		return
	}
}
