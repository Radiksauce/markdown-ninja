package service

import (
	"context"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
)

func (service *ContactsService) DeleteSession(ctx context.Context, db db.Queryer, sessionID guid.GUID) (err error) {
	err = service.repo.DeleteSession(ctx, db, sessionID)
	return
}
