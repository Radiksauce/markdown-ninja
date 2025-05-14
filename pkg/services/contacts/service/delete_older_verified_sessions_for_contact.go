package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

func (service *ContactsService) DeleteOlderVerifiedSessionsForContact(ctx context.Context, db db.Queryer, contactID guid.GUID) (err error) {
	err = service.repo.DeleteOlderVerifiedSessionsForContact(ctx, db, contactID, 10)
	return
}
