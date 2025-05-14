package service

import (
	"context"
	"fmt"
	"time"

	"github.com/stripe/stripe-go/v81"
	striperefund "github.com/stripe/stripe-go/v81/refund"
	"markdown.ninja/pkg/services/store"
)

func (service *StoreService) JobSyncRefundWithStripe(ctx context.Context, input store.JobSyncRefundWithStripe) (err error) {
	refund, err := service.repo.FindRefundByID(ctx, service.db, input.RefundID)
	if err != nil {
		return
	}

	// Stripe refund not created yet
	if refund.StripeRefundID == nil {
		return
	}

	stripeRefundParams := &stripe.RefundParams{}
	stripeRefund, err := striperefund.Get(*refund.StripeRefundID, stripeRefundParams)
	if err != nil {
		err = fmt.Errorf("store.JobSyncRefundWithStripe: error fetching Stripe refund (%s): %w", refund.ID.String(), err)
		return
	}

	refundStatus := store.RefundStatus(stripeRefund.Status)
	if refundStatus != refund.Status {
		refund.UpdatedAt = time.Now().UTC()
		refund.Status = refundStatus
		// TODO: it's weird, the field should be nullable, but it's not in the Go object
		if stripeRefund.FailureReason != "" {
			failureReason := store.RefundFailureReason(stripeRefund.FailureReason)
			refund.FailureReason = &failureReason
		}
		err = service.repo.UpdateRefund(ctx, service.db, refund)
		if err != nil {
			return
		}
	}

	return
}
