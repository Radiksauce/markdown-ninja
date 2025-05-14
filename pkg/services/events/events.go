package events

import (
	"fmt"
)

type EventType int64

// We need to alias guid.GUID, otherwise the serialization to JSON will not be a valid guid.GUID string
// which is required to get the most performance out of Postgres
// type guid.GUID guid.GUID

// MarshalText implements encoding.TextMarshaler.
// func (uuid guid.GUID) MarshalText() ([]byte, error) {
// 	ret := guid.GUID(uuid).ToUuidString()
// 	return []byte(ret), nil
// }

const (
	EventTypePageView EventType = iota
	EventTypeCustom
	EventTypeSubscribedToNewsletter
	EventTypeUnsubscribedFromNewsletter
	EventTypeEmailSent
	EventTypeOrderPlaced
	EventTypeOrderCanceled
	EventTypeOrderCompleted
)

// MarshalText implements encoding.TextMarshaler.
func (eventType EventType) MarshalText() (ret []byte, err error) {
	switch eventType {
	case EventTypePageView:
		ret = []byte("page_view")
	case EventTypeCustom:
		ret = []byte("custom")
	case EventTypeSubscribedToNewsletter:
		ret = []byte("subscribed_to_newsletter")
	case EventTypeUnsubscribedFromNewsletter:
		ret = []byte("unsubscribed_from_newsletter")
	case EventTypeEmailSent:
		ret = []byte("email_sent")
	case EventTypeOrderPlaced:
		ret = []byte("order_placed")
	case EventTypeOrderCompleted:
		ret = []byte("order_completed")
	case EventTypeOrderCanceled:
		ret = []byte("order_canceled")
	default:
		err = fmt.Errorf("Unknown EventType: %d", eventType)
	}
	return
}

func (eventType EventType) String() string {
	ret, _ := eventType.MarshalText()
	return string(ret)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (eventType *EventType) UnmarshalText(data []byte) (err error) {
	switch string(data) {
	case "page_view":
		*eventType = EventTypePageView
	case "custom":
		*eventType = EventTypeCustom
	case "subscribed_to_newsletter":
		*eventType = EventTypeSubscribedToNewsletter
	case "unsubscribed_from_newsletter":
		*eventType = EventTypeUnsubscribedFromNewsletter
	case "email_sent":
		*eventType = EventTypeEmailSent
	case "order_placed":
		*eventType = EventTypeOrderPlaced
	case "order_completed":
		*eventType = EventTypeOrderCompleted
	case "order_canceled":
		*eventType = EventTypeOrderCanceled
	default:
		err = fmt.Errorf("Unknown EventType: %s", string(data))
	}
	return nil
}

type EventDataPageView struct{}

type EventDataCustom struct {
	EventName string `json:"event_name"`
}

type EventDataSubscribedToNewsletter struct {
}

type EventDataUnsubscribedFromNewsletter struct {
}

type EventDataEmailSent struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

type EventDataOrderPlaced struct {
}

type EventDataOrderCanceled struct {
}

type EventDataOrderCompleted struct {
	TotalAmount int64 `json:"total_amount"`
}

type EventData interface {
	EventType() string
}
