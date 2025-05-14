package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) ListCoupons(ctx context.Context, input store.ListCouponsInput) (ret kernel.PaginatedResult[store.Coupon], err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	ret.Data, err = service.repo.FindCouponsByWebsiteID(ctx, service.db, input.WebsiteID)
	if err != nil {
		return
	}

	return
}
