package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/contacts"
)

// TODO: we ca re-enable this job and the associated task only to delete contacts that didn't complete an order yet
// Indeed, a contact can have performed an order but is not verified yet
func (service *ContactsService) JobDeleteOldUnverifiedContacts(ctx context.Context, data contacts.JobDeleteOldUnverifiedContacts) (err error) {
	now := time.Now().UTC()
	// Delete unverified contacts older than 2 weeks
	twoWeeksAgo := now.Add(-14 * 24 * time.Hour)

	err = service.repo.DeleteOldUnverifiedContacts(ctx, service.db, twoWeeksAgo)
	if err != nil {
		return
	}

	return
}
