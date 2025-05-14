package service

import (
	"context"
	"strings"
	"time"

	"github.com/bloom42/stdx-go/countries"
	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/contacts"
	"markdown.ninja/pkg/services/kernel"
)

func (service *ContactsService) CreateContact(ctx context.Context, input contacts.CreateContactInput) (contact contacts.Contact, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
	if err != nil {
		return
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))
	name := strings.TrimSpace(input.Name)

	err = service.ValidateContactEmail(ctx, email, false)
	if err != nil {
		return
	}

	err = service.ValidateContactName(name)
	if err != nil {
		return
	}

	// chack that contact with same email doesn't already exists
	_, err = service.repo.FindContactByEmail(ctx, service.db, input.WebsiteID, email)
	if err == nil {
		err = contacts.ErrContactWithEmailAlreadyExists(email)
		return
	} else {
		if !errs.IsNotFound(err) {
			return
		}
		err = nil
	}

	createContactInput := contacts.CreateContactInternalInput{
		Name:        name,
		Email:       email,
		Verified:    true,
		WebsiteID:   input.WebsiteID,
		CountryCode: countries.CodeUnknown,
	}
	contact, err = service.CreateContactInternal(ctx, service.db, createContactInput)
	if err != nil {
		return
	}

	return
}

func (service *ContactsService) CreateContactInternal(ctx context.Context, db db.Queryer, input contacts.CreateContactInternalInput) (contact contacts.Contact, err error) {
	now := time.Now().UTC()
	var subscribedToNewsletterAt *time.Time

	if input.Name == "" {
		input.Name = service.extractNameFromEmail(input.Email)
	}

	if input.SubscribedToNewsletter {
		subscribedToNewsletterAt = &now
	}

	if input.CountryCode == "" {
		httpCtx := httpctx.FromCtx(ctx)
		if httpCtx != nil {
			input.CountryCode = httpCtx.Client.CountryCode
		}
	}
	if input.CountryCode == "" {
		input.CountryCode = countries.CodeUnknown
	}

	contactID := guid.NewTimeBased()

	contact = contacts.Contact{
		ID:                           contactID,
		CreatedAt:                    now,
		UpdatedAt:                    now,
		Name:                         input.Name,
		Email:                        input.Email,
		SubscribedToNewsletterAt:     subscribedToNewsletterAt,
		SubscribedToProductUpdatesAt: &now,
		Verified:                     input.Verified,
		CountryCode:                  input.CountryCode,
		FailedSignupAttempts:         0,
		SignupCodeHash:               input.SignupCodeHash,
		BillingAddress: kernel.Address{
			Line1:       "",
			Line2:       "",
			PostalCode:  "",
			City:        "",
			State:       "",
			CountryCode: input.CountryCode,
		},
		StripeCustomerID: nil,
		WebsiteID:        input.WebsiteID,
	}
	err = service.repo.CreateContact(ctx, db, contact)
	if err != nil {
		return
	}

	return
}
