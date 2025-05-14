package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) ListRefunds(ctx context.Context, input store.ListRefundsInput) (ret kernel.PaginatedResult[store.Refund], err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	limit := int64(100)
	ret.Data, err = service.repo.FindRefundsByWebsiteID(ctx, service.db, input.WebsiteID, limit)
	if err != nil {
		return
	}

	return
}
