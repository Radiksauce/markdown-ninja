package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/bloom42/stdx-go/crypto/blake3"
	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/billing/meterevent"
	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/services/organizations"
)

// https://docs.stripe.com/api/v2/billing/meter-event/create?lang=go
// type stripeMeterEventV2 struct {
// 	// A unique identifier for the event.
// 	// If not provided, one will be generated. We recommend using a globally unique identifier for this.
// 	// We'll enforce uniqueness within a rolling 24 hour period.
// 	Identifier string `json:"identifier"`
// 	// The name of the meter event. Corresponds with the event_name field on a meter.
// 	EventName string `json:"event_name"`
// 	// The time of the event. Must be within the past 35 calendar days or up to 5 minutes in the future.
// 	// Defaults to current timestamp if not specified.
// 	Timestamp time.Time `json:"timestamp"`
// 	Payload   struct {
// 		StripeCustomerID string `json:"stripe_customer_id"`
// 		Value            string `json:"value"`
// 	} `json:"payload"`
// }

func (service *OrganizationsService) JobSendUsageData(ctx context.Context, input organizations.JobSendUsageData) (err error) {
	logger := slogx.FromCtx(ctx)

	err = service.db.Transaction(ctx, func(tx db.Tx) (txErr error) {
		organization, txErr := service.repo.FindOrganizationByID(ctx, service.db, input.OrganizationID, true)
		if txErr != nil {
			if errs.IsNotFound(txErr) {
				logger.Warn("organizations.JobSendOrganizationUsageData: organization not found",
					slog.String("organization.id", input.OrganizationID.String()))
				return nil
			}
			return txErr
		}

		txErr = service.sendOrganizationUsageData(ctx, tx, &organization)
		if txErr != nil {
			return txErr
		}

		return service.repo.UpdateOrganization(ctx, service.db, organization)
	})
	if err != nil {
		return
	}

	return
}

// if orgazation.StripeCustomerID || organization.StripeSubscriptionID are null then this function does nothing.
// organization.UsageLastSentAt will be updated with the current timestamp.
func (service *OrganizationsService) sendOrganizationUsageData(ctx context.Context, db db.Queryer, organization *organizations.Organization) (err error) {
	now := time.Now().UTC()
	to := now
	// by default we use the first day of the month at 00:00:00
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if organization.UsageLastSentAt != nil {
		from = *organization.UsageLastSentAt
	}

	if organization.StripeCustomerID == nil || organization.StripeSubscriptionID == nil {
		return nil
	}

	emailsSent, err := service.eventsService.GetEmailsSentCountForOrganization(ctx, db, organization.ID, from, to)
	if err != nil {
		return err
	}

	if emailsSent == 0 {
		return nil
	}

	idempotencyString := fmt.Sprintf("%d-%d-%s", from.UnixMicro(), to.UnixMicro(), organization.ID.String())
	idempotencyHash := blake3.Sum256([]byte(idempotencyString))
	idempotencyIdentifier := base64.RawURLEncoding.EncodeToString(idempotencyHash[:])
	params := &stripe.BillingMeterEventParams{
		EventName: stripe.String(organizations.StripeMeterEmails),
		Payload: map[string]string{
			"value":              strconv.FormatInt(emailsSent, 10),
			"stripe_customer_id": *organization.StripeCustomerID,
		},
		Identifier: stripe.String(idempotencyIdentifier),
		Timestamp:  stripe.Int64(now.Unix()),
	}
	_, err = meterevent.New(params)
	if err != nil {
		err = fmt.Errorf("sending emails usage data to Stripe for organization [%s]: %w", organization.ID, err)
		return
	}

	organization.UsageLastSentAt = &now

	return
}
