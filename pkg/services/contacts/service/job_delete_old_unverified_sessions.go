package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/contacts"
)

func (service *ContactsService) JobDeleteOldUnverifiedSessions(ctx context.Context, data contacts.JobDeleteOldUnverifiedSessions) (err error) {
	now := time.Now().UTC()
	// Delete unverified sessions older than 6 hours
	createdBefore := now.Add(-6 * time.Hour)

	err = service.repo.DeleteOldUnverifiedSessions(ctx, service.db, createdBefore)
	if err != nil {
		return
	}

	return
}
