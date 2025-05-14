package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) FindContact(ctx context.Context, db db.Queryer, contactID guid.GUID) (contact contacts.Contact, err error) {
	contact, err = service.repo.FindContactByID(ctx, db, contactID)
	return
}
