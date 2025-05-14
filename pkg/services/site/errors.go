package site

import "markdown.ninja/pkg/errs"

var (
	// Contacts
	ErrAccountNotFound          = errs.NotFound("Account not found. Please create an account.")
	ErrAccountAlreadyExists     = errs.InvalidArgument("Account already exists. Please log in instead.")
	ErrAuthCodeInvalidOrExpired = errs.PermissionDenied("Code is invalid or has expired. Please reload the page and try again.")
	ErrMaxSignupAttempsReached  = errs.PermissionDenied("Max confirmation attempts reached. Please reload the page and signup again.")
	ErrAccountBlocked           = errs.PermissionDenied("Account locked. Please contact support.")

	// Websites
	ErrSiteNotFound = errs.NotFound("Website not found.")

	// content
	ErrRangeRequestIsNotValid = errs.InvalidArgument("Range request is not valid")
)
