package service

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/bloom42/stdx-go/guid"
	"github.com/bloom42/stdx-go/log/slogx"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/taxid"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) getStripeCheckoutSessionLineItemsForPlan(planID kernel.PlanID, extraSlots int64) (lineItems []*stripe.CheckoutSessionLineItemParams, err error) {
	switch planID {
	case kernel.PlanPro.ID:
		lineItems = []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(service.stripeConfig.Prices.Pro),
				Quantity: stripe.Int64(1),
			},
			{
				Price: stripe.String(service.stripeConfig.Prices.Emails),
			},
		}

	default:
		err = fmt.Errorf("getting Stripe checkout session line items: unknwon plan: %s", planID)
		return
	}

	if extraSlots != 0 {
		lineItems = append(lineItems, &stripe.CheckoutSessionLineItemParams{
			Price:    stripe.String(service.stripeConfig.Prices.Slots),
			Quantity: &extraSlots,
		})
	}

	return
}

func (service *OrganizationsService) getStripeSubscriptionLineItemsForPlan(planID kernel.PlanID, extraSlots int64) (lineItems []*stripe.SubscriptionItemsParams, err error) {
	switch planID {
	case kernel.PlanPro.ID:
		lineItems = []*stripe.SubscriptionItemsParams{
			{
				Price:    stripe.String(service.stripeConfig.Prices.Pro),
				Quantity: stripe.Int64(1),
			},
			{
				Price: stripe.String(service.stripeConfig.Prices.Emails),
			},
		}

	default:
		err = fmt.Errorf("getting Stripe subscription line items: unknwon plan: %s", planID)
		return
	}

	if extraSlots != 0 {
		lineItems = append(lineItems, &stripe.SubscriptionItemsParams{
			Price:    stripe.String(service.stripeConfig.Prices.Slots),
			Quantity: &extraSlots,
		})
	}

	return
}

func (service *OrganizationsService) generateStripeCheckoutSessionSuccessUrl(organizationID guid.GUID, planID kernel.PlanID) string {
	query := url.Values{}
	query.Add("plan", string(planID))

	successUrl := url.URL{
		Scheme:   service.httpConfig.WebappBaseUrl.Scheme,
		Host:     fmt.Sprintf("%s%s", service.httpConfig.WebappDomain, service.httpConfig.WebappPort),
		Path:     fmt.Sprintf("/organizations/%s/billing/checkout/complete", organizationID),
		RawQuery: query.Encode(),
	}
	return successUrl.String()
}

func (service *OrganizationsService) generateOrganizationBillingUrl(organizationID guid.GUID) (link string) {
	billingUrl := url.URL{
		Scheme: service.httpConfig.WebappBaseUrl.Scheme,
		Host:   fmt.Sprintf("%s%s", service.httpConfig.WebappDomain, service.httpConfig.WebappPort),
		Path:   fmt.Sprintf("/organizations/%s/billing", organizationID),
	}
	return billingUrl.String()
}

func (service *OrganizationsService) generateStripeCheckoutSessionParams(organization organizations.Organization, planID kernel.PlanID, billingAnchor time.Time, lineItems []*stripe.CheckoutSessionLineItemParams) (stripeCheckoutSessionParams *stripe.CheckoutSessionParams) {
	// if the stripe customer already exists, and the billing address is not empty then we don't ask for the billing address
	billingAddressCollection := stripe.CheckoutSessionBillingAddressCollectionRequired
	customerUpdateAddress := "auto"

	if organization.StripeCustomerID != nil && organization.BillingInformation.AddressLine1 != "" {
		billingAddressCollection = stripe.CheckoutSessionBillingAddressCollectionAuto
		customerUpdateAddress = "never"
	}

	// https://docs.stripe.com/api/checkout/sessions/create
	stripeCheckoutSessionParams = &stripe.CheckoutSessionParams{
		Customer: organization.StripeCustomerID,
		CustomerUpdate: &stripe.CheckoutSessionCustomerUpdateParams{
			Name:    stripe.String("auto"),
			Address: stripe.String(customerUpdateAddress),
		},
		BillingAddressCollection: stripe.String(string(billingAddressCollection)),
		Mode:                     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems:                lineItems,
		SuccessURL:               stripe.String(service.generateStripeCheckoutSessionSuccessUrl(organization.ID, planID)),
		CancelURL:                stripe.String(service.generateOrganizationBillingUrl(organization.ID)),
		SavedPaymentMethodOptions: &stripe.CheckoutSessionSavedPaymentMethodOptionsParams{
			AllowRedisplayFilters: []*string{
				stripe.String(string(stripe.CheckoutSessionSavedPaymentMethodOptionsAllowRedisplayFilterAlways)),
			},
			// for subscriptions the payment method is already saved by default, so there is no need to enable this
			// PaymentMethodSave: stripe.String(string(stripe.CheckoutSessionSavedPaymentMethodOptionsPaymentMethodSaveEnabled)),
		},
		// PaymentMethodCollection: stripe.String(string(stripe.CheckoutSessionPaymentMethodCollectionAlways)),
		// PaymentMethodOptions: &stripe.CheckoutSessionPaymentMethodOptionsParams{
		// 	Card: &stripe.CheckoutSessionPaymentMethodOptionsCardParams{

		// 	},
		// },
		// AutomaticTax: &stripe.CheckoutSessionAutomaticTaxParams{
		// 	Enabled: stripe.Bool(true),
		// },
		// Can't pass PaymentIntentData in subscription mode
		// PaymentIntentData: &stripe.CheckoutSessionPaymentIntentDataParams{
		// 	SetupFutureUsage: stripe.String(string(stripe.SetupIntentUsageOffSession)),
		// 	Metadata: map[string]string{
		// 		"markdown_ninja_organization_id": organization.ID.String(),
		// 	},
		// },
		TaxIDCollection: &stripe.CheckoutSessionTaxIDCollectionParams{
			Enabled:  stripe.Bool(true),
			Required: stripe.String(string(stripe.CheckoutSessionTaxIDCollectionRequiredNever)),
		},
		Metadata: map[string]string{
			"markdown_ninja_organization_id": organization.ID.String(),
			"markdown_ninja_plan":            string(planID),
		},
		SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
			BillingCycleAnchor: stripe.Int64(billingAnchor.Unix()),
			Metadata: map[string]string{
				"markdown_ninja_organization_id": organization.ID.String(),
				"markdown_ninja_plan":            string(planID),
			},
		},
	}
	return
}

func (service *OrganizationsService) generateStrieCustomerParams(organization organizations.Organization) (stripeCustomerParams *stripe.CustomerParams) {
	var stripeCustomerTaxIdData []*stripe.CustomerTaxIDDataParams

	if organization.BillingInformation.TaxID != nil {
		stripeCustomerTaxIdData = []*stripe.CustomerTaxIDDataParams{
			{
				Type:  stripe.String(string(stripe.TaxIDTypeEUVAT)),
				Value: organization.BillingInformation.TaxID,
			},
		}
	}

	stripeCustomerParams = &stripe.CustomerParams{
		Name:  stripe.String(organization.BillingInformation.Name),
		Email: stripe.String(organization.BillingInformation.Email),
		Address: &stripe.AddressParams{
			Line1:      stripe.String(organization.BillingInformation.AddressLine1),
			Line2:      stripe.String(organization.BillingInformation.AddressLine2),
			City:       stripe.String(organization.BillingInformation.City),
			PostalCode: stripe.String(organization.BillingInformation.PostalCode),
			State:      stripe.String(organization.BillingInformation.State),
			Country:    stripe.String(organization.BillingInformation.CountryCode),
		},
		TaxIDData: stripeCustomerTaxIdData,
		Metadata: map[string]string{
			"markdown_ninja_organization_id": organization.ID.String(),
		},
	}
	return
}

func (service *OrganizationsService) fetchStripeTaxIDsForCustomer(stripeCustomerID string) (taxIDs []*stripe.TaxID, err error) {
	taxIdsParams := &stripe.TaxIDListParams{Customer: &stripeCustomerID}
	taxIdsParams.Limit = stripe.Int64(1)

	stripeCustomerTaxIds := taxid.List(taxIdsParams)
	if stripeCustomerTaxIds.Err() != nil {
		err = fmt.Errorf("error fetching stripe taxIDs: %w", err)
		return
	}

	taxIDs = stripeCustomerTaxIds.TaxIDList().Data
	return
}

// update Stripe Tax ID for the Stripe Customer associated with the organization so that it matches
// the billing informaiton of the organization.
// Do nothing if the Stripe tax ID is up to date with the organization's billing information
func (service *OrganizationsService) updateStripeTaxIDIfNeeded(ctx context.Context, organization organizations.Organization, existingTaxIDs []*stripe.TaxID) (err error) {
	logger := slogx.FromCtx(ctx)
	if organization.StripeCustomerID == nil {
		return fmt.Errorf("organizations.updateStripeTaxIDIfNeeded: organization [%s] has no StripeCustomerID attached", organization.ID)
	}

	if organization.BillingInformation.TaxID != nil {
		if len(existingTaxIDs) == 0 {
			logger.Debug("organizations.updateStripeTaxIDIfNeeded: creating Stripe tax ID")
			// create stripe tax ID
			createTaxIdParams := &stripe.TaxIDParams{
				Type:     stripe.String(string(stripe.TaxIDTypeEUVAT)),
				Value:    organization.BillingInformation.TaxID,
				Customer: organization.StripeCustomerID,
			}
			_, err = taxid.New(createTaxIdParams)
			err = fmt.Errorf("organizations.updateStripeTaxIDIfNeeded: creating stripe tax ID: %w", err)
			if err != nil {
				return
			}
		} else if len(existingTaxIDs) != 0 && existingTaxIDs[0].Value != *organization.BillingInformation.TaxID {
			// Update tax ID
			// tax IDs need to be deleted and re-created to be updated
			// See https://docs.stripe.com/billing/customer/tax-ids

			logger.Debug("organizations.updateStripeTaxIDIfNeeded: updating Stripe tax ID")
			for _, stripeTaxId := range existingTaxIDs {
				deleteTaxIdParams := &stripe.TaxIDParams{Customer: stripe.String(*organization.StripeCustomerID)}
				_, err = taxid.Del(stripeTaxId.ID, deleteTaxIdParams)
				if err != nil {
					err = fmt.Errorf("organizations.updateStripeTaxIDIfNeeded: updating stripe tax ID [%s] (delete): %w", stripeTaxId.ID, err)
					return
				}
			}

			createTaxIdParams := &stripe.TaxIDParams{
				Type:     stripe.String(string(stripe.TaxIDTypeEUVAT)),
				Value:    organization.BillingInformation.TaxID,
				Customer: organization.StripeCustomerID,
			}
			_, err = taxid.New(createTaxIdParams)
			err = fmt.Errorf("organizations.updateStripeTaxIDIfNeeded: updating stripe tax ID (creating): %w", err)
			if err != nil {
				return
			}
		}
	} else {
		if len(existingTaxIDs) != 0 {
			logger.Debug("organizations.updateStripeTaxIDIfNeeded: deleting Stripe tax ID")
			// delete stripe tax ID
			for _, stripeTaxId := range existingTaxIDs {
				deleteTaxIdParams := &stripe.TaxIDParams{Customer: stripe.String(*organization.StripeCustomerID)}
				_, err = taxid.Del(stripeTaxId.ID, deleteTaxIdParams)
				if err != nil {
					err = fmt.Errorf("organizations.updateStripeTaxIDIfNeeded: deleting stripe tax ID [%s]: %w", stripeTaxId.ID, err)
					return
				}
			}
		}
	}
	return
}
