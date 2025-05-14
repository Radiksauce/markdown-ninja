package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/events"
)

func (service *Service) TrackOrderPlaced(ctx context.Context, input events.TrackOrderPlacedInput) {
	go service.trackOrderPlacedInBackground(input)
}

func (service *Service) trackOrderPlacedInBackground(input events.TrackOrderPlacedInput) {
	now := time.Now().UTC()

	browser, os, _ := service.parseUserAgent(input.UserAgent)

	event := events.Event{
		Time:            now,
		Type:            events.EventTypeOrderPlaced,
		Data:            events.EventDataOrderPlaced{},
		Browser:         &browser,
		OperatingSystem: &os,
		Country:         &input.Country,
		WebsiteID:       input.WebsiteID,
		OrderID:         &input.OrderID,
	}

	service.eventsBuffer.Push(event)
}
