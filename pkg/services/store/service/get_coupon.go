package service

import (
	"context"

	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) GetCoupon(ctx context.Context, input store.GetCouponInput) (coupon store.Coupon, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	coupon, err = service.repo.FindCouponByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, coupon.WebsiteID)
	if err != nil {
		return
	}

	err = service.hydrateCoupon(ctx, service.db, &coupon)
	if err != nil {
		return
	}

	return
}
