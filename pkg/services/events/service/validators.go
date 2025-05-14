package service

import (
	"fmt"

	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/services/events"
)

func (service *Service) validateCustomEventName(eventName string) (err error) {
	if len(eventName) > events.CustomEventNameMaxSize {
		return errs.InvalidArgument(fmt.Sprintf("custom event name is too long. max: %d characters", events.CustomEventNameMaxSize))
	}

	if eventName == "" {
		return errs.InvalidArgument("custom event name is empty")
	}

	return nil
}
