package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) TrackOrderCompleted(ctx context.Context, input events.TrackOrderCompletedInput) {
	go service.trackOrderCompletedInBackground(ctx, input)
}

func (service *Service) trackOrderCompletedInBackground(ctx context.Context, input events.TrackOrderCompletedInput) {
	now := time.Now().UTC()
	event := events.Event{
		Time: now,
		Type: events.EventTypeOrderCompleted,
		Data: events.EventDataOrderCompleted{
			TotalAmount: input.TotalAmount,
		},
		WebsiteID: input.WebsiteID,
		OrderID:   &input.OrderID,
	}

	service.eventsBuffer.Push(event)
}
