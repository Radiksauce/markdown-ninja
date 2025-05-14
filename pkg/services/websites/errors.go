package websites

import (
	"fmt"
	"net/http"

	"markdown.ninja/pkg/errs"
)

var (
	// Websites
	ErrWebsiteNameIsTooShort   = errs.InvalidArgument("Website name is too short.")
	ErrWebsiteNameIsTooLong    = errs.InvalidArgument("Website name is too long.")
	ErrWebsiteNameIsNotValid   = errs.InvalidArgument("Website name is not valid.")
	ErrWebsiteSlugIsTooShort   = errs.InvalidArgument("Subdomain is too short.")
	ErrWebsiteSlugIsTooLong    = errs.InvalidArgument("Subdomain is too long.")
	ErrWebsiteSlugIsNotValid   = errs.InvalidArgument("Subdomain is not valid.")
	ErrWebsiteSlugNotAvailable = errs.InvalidArgument("Subdomain is not available.")
	ErrWebsiteNotFound         = errs.NotFound("Website not found.")
	ErrEmailInfoNotFound       = errs.NotFound("Email info not found.")
	ErrInvalidLanguage         = errs.InvalidArgument("Language is not valid.")
	ErrRemovingEmailDomain     = func(hostname string) error {
		return errs.InvalidArgument(fmt.Sprintf("Error removing email domain: \"%s\"", hostname))
	}
	ErrWebsiteHeaderIsTooLong        = errs.InvalidArgument(fmt.Sprintf("Header is too long. Max size is: %d characters", WebsiteHeaderMaxLength))
	ErrWebsiteHeaderIsNotValid       = errs.InvalidArgument("Header is not valid")
	ErrWebsiteFooterIsTooLong        = errs.InvalidArgument(fmt.Sprintf("Footer is too long. Max size is: %d characters", WebsiteFooterMaxLength))
	ErrWebsiteFooterIsNotValid       = errs.InvalidArgument("Footer is not valid")
	ErrWebsiteDescriptionIsTooLong   = errs.InvalidArgument(fmt.Sprintf("Descrption is too long. Max size is: %d characters", WebsiteDescriptionMaxLength))
	ErrWebsiteDescriptionIsNotValid  = errs.InvalidArgument("Description is not valid")
	ErrThemeIsNotValid               = errs.InvalidArgument("Theme is not valid")
	ErrCantDeleteWebsiteWithProducts = errs.InvalidArgument("Please delete your products before deleting the website")
	ErrRobotsTxtIsTooLong            = errs.InvalidArgument("Your robots.txt file is too long")
	ErrRobotsTxtIsNotValid           = errs.InvalidArgument("Your robots.txt file is not valid")
	ErrWebsiteIconIsNotValid         = errs.InvalidArgument("Icon is not valid. The image must be a square PNG file with a minimum resolution of 256x256 pixels.")
	ErrAdIsNotValid                  = errs.InvalidArgument("Ad is not valid")
	ErrAnnouncementIsNotValid        = errs.InvalidArgument("Announcement is not valid")
	ErrLogoUrlisNotValid             = errs.InvalidArgument("Logo URL is not valid")

	// Staff
	ErrStaffNotFound      = errs.NotFound("Staff not found")
	ErrUserIsAlreadyStaff = func(email, websiteName string) error {
		return errs.PermissionDenied(fmt.Sprintf("%s is already staff of %s.", email, websiteName))
	}
	ErrStaffInvitationNotFound = errs.NotFound("Invitation not found.")
	ErrCantRemoveLastStaff     = errs.InvalidArgument("You can't remove last staff.")
	ErrStaffRoleIsNotValid     = errs.InvalidArgument("Role is not valid.")

	// redirects
	ErrRedirectStatusIsNotValid      = errs.InvalidArgument(fmt.Sprintf("Redirect status is no. Valid values are [%d, %d]", http.StatusFound, http.StatusMovedPermanently))
	ErrRedirectPatternIsNotValid     = errs.InvalidArgument("Redirect pattern is not valid")
	ErrRedirectDestinationIsNotValid = errs.InvalidArgument("Redirect destination is not valid")

	// Themes
	ErrOpeningTemplate = func(file string, err error) error {
		return errs.InvalidArgument(fmt.Sprintf("Opening template (%s): %s", file, err))
	}
	ErrGettingTemplateInfo = func(file string, err error) error {
		return errs.InvalidArgument(fmt.Sprintf("Getting template info (%s): %s", file, err))
	}
	ErrTempalteIsNotAFile = func(file string) error {
		return errs.InvalidArgument(fmt.Sprintf("Template is not a file (%s)", file))
	}
	ErrOpeningThemeAssets = func(err error) error {
		return errs.InvalidArgument(fmt.Sprintf("Opening theme assets: %s", err))
	}
	ErrOpeningThemeDirectory = func(err error) error {
		return errs.InvalidArgument(fmt.Sprintf("Opening theme directory: %s", err))
	}

	// Domains
	ErrDomainNameIsNotValid     = errs.InvalidArgument("Domain name is not valid.")
	ErrDomainNameIsAlreadyInUse = errs.InvalidArgument("Domain name is already in use.")
	ErrDomainNotFound           = errs.NotFound("Domain not found.")
	ErrAddingDomain             = func(hostname string) error {
		return errs.InvalidArgument(fmt.Sprintf("Error adding domain: %s. Please contact support if the problem persists.", hostname))
	}
	ErrRemovingDomain = func(hostname string) error {
		return errs.InvalidArgument(fmt.Sprintf("Error removing domain: %s. Please contact support if the problem persists.", hostname))
	}
	ErrGettingTlsCertificate = errs.InvalidArgument("Error getting TLS certificate. Please verify your DNS settings and try again later.")

	// Currencies
	ErrCurrencyIsNotValid = errs.InvalidArgument("currency is not valid")
)
