package kernel

import (
	"markdown.ninja/pkg/errs"
)

var (
	// Auth
	ErrAuthenticationRequired    = errs.AuthenticationRequired("Permission denied: authentication required")
	ErrMustNotBeAuthenticated    = errs.PermissionDenied("Permission denied: must not be authenticated")
	ErrApiRequiresAuthentication = errs.PermissionDenied("Permission denied: authentication is required to call the API")
	ErrPermissionDenied          = errs.PermissionDenied("Permission denied")
	ErrSessionIsNotValid         = errs.PermissionDenied("Session is not valid. Please reload page.")
	ErrTokenIsNotValid           = errs.PermissionDenied("Token is not valid.")
	ErrApiKeyIsNotValid          = errs.PermissionDenied("Api Key is not valid.")
	ErrChallengeIsNotValid       = errs.PermissionDenied("Captcha is not valid")

	ErrMaxLoginAttempsReached  = errs.PermissionDenied("Max confirmation attempts reached. Please login again.")
	ErrAuthCodeIsNotValid      = errs.PermissionDenied("Code is not valid. Please try again.")
	ErrLoginCodeExpired        = errs.PermissionDenied("Code expired. Please login again.")
	ErrMaxSignupAttempsReached = errs.PermissionDenied("Max confirmation attempts reached. Please create a new account.")
	ErrSignupCodeExpired       = errs.PermissionDenied("Code expired. Please create a new account.")
	ErrInvalidEmailPassword    = errs.PermissionDenied("Invalid Email or Password Combination")

	ErrTwoFaAlreadyEnabled = errs.InvalidArgument("2FA Already enabled.")
	ErrTwoFaIsNotEnabled   = errs.InvalidArgument("2FA Is not enabled.")
	ErrTwoFaCodeIsNotValid = errs.InvalidArgument("2Fa Code is not valid.")

	// Users
	ErrRegistrationBlockedInLocation = errs.PermissionDenied("Registrations are disabled in your location.")
	ErrAuthenticationBlockedForTor   = errs.PermissionDenied("Authentication is currently disabled for Tor to protect against abuse.")
	ErrUserIsBlocked                 = errs.PermissionDenied("Your account is deactivated. Please contact support to re-activate your account.")
	ErrUserIsAlreadyBlocked          = errs.PermissionDenied("User is already blocked.")
	ErrUserIsNotBlocked              = errs.PermissionDenied("User is not blocked.")
	ErrAdminsCantBeBlocked           = errs.PermissionDenied("Administrators can't be blocked.")
	ErrSignupsAreClosed              = errs.PermissionDenied("Singups are closed. Please contact support.")
	ErrEmailAlreadyInUse             = errs.AlreadyExists("An account with this email already exsits. Try to log in instead.")
	ErrEmailIsTooLong                = errs.AlreadyExists("Email is too long")
	ErrEmailIsNotValid               = errs.InvalidArgument("Email is not valid")
	ErrUserNotFound                  = errs.NotFound("User not found.")

	ErrPendingEmailNotFound   = errs.NotFound("Email not found.")
	ErrAdminUserCantBeDeleted = errs.InvalidArgument("Admin user can't be deleted. Please remove admin role before deleting user.")

	// Background Jobs
	ErrOnlyFailedJobsCanBeDeleted = errs.InvalidArgument("Only failed jobs can be deleted")

	// utils
	ErrColorIsNotValid = errs.InvalidArgument("Color is not valid")
)
