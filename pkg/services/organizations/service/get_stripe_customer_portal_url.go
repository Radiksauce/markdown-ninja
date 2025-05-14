package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/stripe/stripe-go/v81"
	portalsession "github.com/stripe/stripe-go/v81/billingportal/session"
	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) GetStripeCustomerPortalUrl(ctx context.Context, input organizations.GetStripeCustomerPortalUrlInput) (ret organizations.GetStripeCustomerPortalUrlOutput, err error) {
	httpCtx := httpctx.FromCtx(ctx)

	if service.isSelfHosted {
		return ret, errs.InvalidArgument("Stripe portal is not available in self-hosted mode")
	}

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	// if current user is not a Markdown Ninja admin then it needs to be an organization admin
	if !httpCtx.AccessToken.IsAdmin {
		var staff organizations.Staff
		staff, err = service.repo.FindStaff(ctx, service.db, actorID, input.OrganizationID)
		if err != nil {
			return
		}

		if staff.Role != organizations.StaffRoleAdministrator {
			err = kernel.ErrPermissionDenied
			return
		}
	}

	organization, err := service.repo.FindOrganizationByID(ctx, service.db, input.OrganizationID, false)
	if err != nil {
		return
	}

	if organization.StripeCustomerID == nil {
		err = errors.New("organizations.GetStripeCustomerPortalUrl: stripeCustomerID is null")
		return
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  organization.StripeCustomerID,
		ReturnURL: stripe.String(service.generateOrganizationBillingUrl(organization.ID)),
	}
	customerPortalSession, err := portalsession.New(params)
	if err != nil {
		err = fmt.Errorf("organizations.GetStripeCustomerPortalUrl: create customer portal session: %w", err)
		return
	}

	ret.StripeCustomerPortalUrl = customerPortalSession.URL
	return
}
