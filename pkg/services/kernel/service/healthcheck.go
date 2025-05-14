package service

import (
	"context"
	"fmt"

	"markdown.ninja/pkg/services/kernel"
)

// TODO: rate limiting
func (service *KernelService) Healthcheck(ctx context.Context, input kernel.EmptyInput) (err error) {
	err = service.db.Ping(ctx)
	if err != nil {
		err = fmt.Errorf("kernel.Healthcheck: %w", err)
		return
	}

	return nil
}
