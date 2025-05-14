package contacts

import (
	"fmt"

	"markdown.ninja/pkg/errs"
)

var (
	// Contacts
	ErrContactNotFound               = errs.NotFound("Contact not found.")
	ErrContactWithEmailAlreadyExists = func(email string) error {
		return errs.InvalidArgument(fmt.Sprintf("Contact with email \"%s\" already exists.", email))
	}
	ErrUnsubscribeTokenIsNotValid   = errs.InvalidArgument("Link is no longer valid.")
	ErrUpdateEmailTokenIsNotValid   = errs.InvalidArgument("Link is no longer valid.")
	ErrImportingContacts            = errs.InvalidArgument("Error importing contacts.")
	ErrImportSubscribedAtIsNotValid = errs.InvalidArgument("Error importing contacts: subscribed_at is not a valid date.")
	ErrImportCsvHeaderisNotValid    = errs.InvalidArgument("Error importing contacts: CSV header not valid.")
	ErrContactIsAlreadyBlocked      = errs.InvalidArgument("Contact is already blocked")
	ErrContactIsNotBlocked          = errs.InvalidArgument("Contact is not blocked")
	ErrUnsubscribeLinkIsNotValid    = errs.InvalidArgument("The link is no longer valid. Please login into your account to unsubscibe.")
	ErrContactNameIsNotValid        = errs.InvalidArgument("Contact name is not valid")

	// Sessions
	ErrSessionNotFound = errs.NotFound("Session not found.")

	// Billing
	ErrBillingInformationNotFound = errs.NotFound("Billing information not found.")

	// Labels
	// ErrLabelNotFound      = errs.NotFound("Label not found.")
	// ErrLabelAlreadyExists = func(name string) error {
	// 	return errs.InvalidArgument(fmt.Sprintf("Label \"%s\" already exists.", name))
	// }
	// ErrLabelDescriptionIsTooLong = errs.InvalidArgument(fmt.Sprintf("Description is too long (max: %d characters)", LabelDescriptionMaxSize))
	// ErrLabelNameIsTooShort       = errs.InvalidArgument(fmt.Sprintf("Name is too short (min: %d characters)", LabelNameMinSize))
	// ErrLabelNameIsTooLong        = errs.InvalidArgument(fmt.Sprintf("Name is too long (max: %d characters)", LabelNameMaxSize))
	// ErrLabelNameMustBeLower      = errs.InvalidArgument("Name must be lowercase")
	// ErrLabelNameIsNotValid       = errs.InvalidArgument("Name is not valid.")
)
