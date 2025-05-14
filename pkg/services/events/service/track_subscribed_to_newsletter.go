package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) TrackSubscribedToNewsletter(ctx context.Context, input events.TrackSubscribedToNewsletterInput) {
	go service.trackSubscribedToNewsletterInBackground(ctx, input)
}

func (service *Service) trackSubscribedToNewsletterInBackground(ctx context.Context, input events.TrackSubscribedToNewsletterInput) {
	now := time.Now().UTC()
	event := events.Event{
		Time:      now,
		Type:      events.EventTypeSubscribedToNewsletter,
		Data:      events.EventDataSubscribedToNewsletter{},
		WebsiteID: input.WebsiteID,
	}

	service.eventsBuffer.Push(event)
}
