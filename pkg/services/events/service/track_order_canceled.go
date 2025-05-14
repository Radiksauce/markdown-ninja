package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) TrackOrderCanceled(ctx context.Context, input events.TrackOrderCanceledInput) {
	go service.trackOrderCanceledInBackground(ctx, input)
}

func (service *Service) trackOrderCanceledInBackground(ctx context.Context, input events.TrackOrderCanceledInput) {
	now := time.Now().UTC()
	event := events.Event{
		Time:      now,
		Type:      events.EventTypeOrderCanceled,
		Data:      events.EventDataOrderCanceled{},
		Country:   &input.Country,
		WebsiteID: input.WebsiteID,
		OrderID:   &input.OrderID,
	}

	service.eventsBuffer.Push(event)
}
