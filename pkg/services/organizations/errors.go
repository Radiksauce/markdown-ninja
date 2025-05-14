package organizations

import (
	"fmt"

	"markdown.ninja/pkg/errs"
)

var (
	// Organizations
	ErrOrganizationNotFound               = errs.NotFound("Organization not found")
	ErrOrganizationNameIsNotValid         = errs.InvalidArgument("Organization name is not valid")
	ErrOrganizationNameIsTooLong          = errs.InvalidArgument(fmt.Sprintf("Name is too long (max: %d characters)", OrganizationNameMaxLength))
	ErrOrganizationNameIsTooShort         = errs.InvalidArgument(fmt.Sprintf("Name is too short (min: %d character)", OrganizationNameMinLength))
	ErrDeleteWebsitesToDeleteOrganization = errs.InvalidArgument("Please delete all your websites before deleting your organization")

	// Staff
	ErrStaffNotFound      = errs.NotFound("Staff not found")
	ErrUserIsAlreadyStaff = func(email, organizationName string) error {
		return errs.PermissionDenied(fmt.Sprintf("%s is already staff of %s.", email, organizationName))
	}
	ErrCantRemoveLastStaff         = errs.InvalidArgument("You can't remove last staff.")
	ErrStaffRoleIsNotValid         = errs.InvalidArgument("Role is not valid.")
	ErrCantRemoveLastAdministrator = errs.InvalidArgument("You can't remove the last administrator from the organization.")

	// Staff invitations
	ErrStaffInvitationNotFound = errs.NotFound("Invitation not found.")

	// ApiKeys
	ErrApiKeyIsMissing      = errs.AuthenticationRequired("Permission denied: API Key is missing")
	ErrApiKeyNotFound       = errs.NotFound("Api Key not found.")
	ErrApiKeyIsNotValid     = errs.InvalidArgument("Api Key is not valid.")
	ErrApiKeyNameIsTooLong  = errs.InvalidArgument("Api Key name is too long (max: 100 characters)")
	ErrApiKeyNameIsTooShort = errs.InvalidArgument("Api Key name is too short (min: 1 character)")
	ErrApiKeyAlreadyExists  = func(name string) error {
		return errs.InvalidArgument(fmt.Sprintf("API Key %s already exists", name))
	}
	ErrApiKeyNameIsNotValid = errs.InvalidArgument("Api Key name is not valid.")

	// Billing
	ErrPlanIsNotValid = errs.InvalidArgument("Plan is not valid")
)
