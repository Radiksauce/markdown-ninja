package emails

import (
	"fmt"

	"markdown.ninja/pkg/errs"
)

var (
	// configuration
	ErrWebsiteConfigurationNotFound = errs.NotFound("Email configuration not found")
	ErrRemovingDomain               = func(domain string) error {
		return errs.InvalidArgument(fmt.Sprintf("Error removing domain: %s", domain))
	}
	ErrDomainAlreadyInUse            = errs.AlreadyExists("This email domain is already in use by another website. Please change and try again or contact support.")
	ErrNoCustomEmailDomainConfigured = errs.InvalidArgument("No custom email domain set up")

	// Newsletter
	ErrNewsletterScheduledForIsInThePast = errs.InvalidArgument("You can't schedule a newsletter in the past")
	ErrNewsletterAlreadySent             = errs.InvalidArgument("Newsletter already sent.")
	ErrNewsletterNotFound                = errs.NotFound("Newsletter not found.")
	ErrNewsletterSubjectIsTooLong        = errs.InvalidArgument(fmt.Sprintf("Subject is too long (max: %d characters)", NewsletterSubjectMaxSize))
	ErrNewsletterSubjectIsTooShort       = errs.InvalidArgument(fmt.Sprintf("Subject is too short (min: %d characters)", NewsletterSubjectMinSize))
	ErrNewsletterBodyIsTooLarge          = errs.InvalidArgument(fmt.Sprintf("Newsletter is too large (max: %d characters)", NewsletterContentMarkdownMaxSize))
	ErrNewsletterSubjectIsNotValid       = errs.InvalidArgument("Newsletter subject is not valid")
	ErrNewsletterBodyIsNotValid          = errs.InvalidArgument("Newsletter body is not valid")
)
