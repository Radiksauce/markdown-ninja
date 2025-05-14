package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) UnblockContact(ctx context.Context, input contacts.UnblockContactInput) (contact contacts.Contact, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	contact, err = service.repo.FindContactByID(ctx, service.db, input.ID)
	if err != nil {
		return
	}

	err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, contact.WebsiteID)
	if err != nil {
		return
	}

	if contact.BlockedAt == nil {
		err = contacts.ErrContactIsNotBlocked
		return
	}

	now := time.Now().UTC()
	contact.UpdatedAt = now
	contact.BlockedAt = nil
	err = service.repo.UpdateContact(ctx, service.db, contact)
	if err != nil {
		return
	}

	return
}
