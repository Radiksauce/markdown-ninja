package service

import (
	"context"
	"fmt"
	"time"

	"github.com/bloom42/stdx-go/queue"
	"markdown.ninja/pkg/services/organizations"
)

func (service *OrganizationsService) JobDispatchSendUsageData(ctx context.Context, _ organizations.JobDispatchSendUsageData) error {
	allOrganizations, err := service.repo.FindAllOrganizations(ctx, service.db)
	if err != nil {
		return err
	}

	jobs := make([]queue.NewJobInput, 0, len(allOrganizations))
	jobScheduledFor := time.Now().UTC()

	for i, organization := range allOrganizations {
		if organization.StripeCustomerID == nil || organization.StripeSubscriptionID == nil {
			continue
		}

		// Limit the number of requests per second
		if i != 0 && i%100 == 0 {
			jobScheduledFor = jobScheduledFor.Add(5 * time.Second)
		}

		job := queue.NewJobInput{
			Data: organizations.JobSendUsageData{
				OrganizationID: organization.ID,
			},
			ScheduledFor: &jobScheduledFor,
		}
		jobs = append(jobs, job)
	}

	err = service.queue.PushMany(ctx, nil, jobs)
	if err != nil {
		return fmt.Errorf("pushing jobs to queue: %w", err)
	}

	return nil
}
