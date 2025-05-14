package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
)

func (service *KernelService) JobRefreshGeoipDatabase(ctx context.Context, input kernel.JobRefreshGeoipDatabase) (err error) {
	return service.geoipResolver.DownloadLatestGeoipDatabase(ctx)
}
