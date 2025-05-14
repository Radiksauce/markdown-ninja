package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) FindContactByEmail(ctx context.Context, db db.Queryer, websiteID guid.GUID, email string) (contact contacts.Contact, err error) {
	contact, err = service.repo.FindContactByEmail(ctx, db, websiteID, email)
	return
}
