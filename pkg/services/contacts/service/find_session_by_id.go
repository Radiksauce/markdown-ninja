package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) FindSessionByID(ctx context.Context, db db.Queryer, sessionID guid.GUID) (session contacts.Session, err error) {
	session, err = service.repo.FindSessionByID(ctx, db, sessionID)
	return
}
