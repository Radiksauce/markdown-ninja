package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) TrackUnsubscribedFromNewsletter(ctx context.Context, input events.TrackUnsubscribedFromNewsletterInput) {
	go service.trackUnsubscribedFromNewsletterInBackground(ctx, input)
}

func (service *Service) trackUnsubscribedFromNewsletterInBackground(ctx context.Context, input events.TrackUnsubscribedFromNewsletterInput) {
	now := time.Now().UTC()
	event := events.Event{
		Time:      now,
		Type:      events.EventTypeUnsubscribedFromNewsletter,
		Data:      events.EventDataUnsubscribedFromNewsletter{},
		WebsiteID: input.WebsiteID,
	}

	service.eventsBuffer.Push(event)
}
