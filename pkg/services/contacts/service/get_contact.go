package service

import (
	"context"

	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) GetContact(ctx context.Context, input contacts.GetContactInput) (contact contacts.Contact, err error) {
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

	contact.Products, err = service.storeService.FindProductsForContact(ctx, service.db, contact.ID)
	if err != nil {
		return
	}

	contact.Orders, err = service.storeService.FindOrdersForContact(ctx, service.db, contact.ID)
	if err != nil {
		return
	}

	return
}
