package content

import (
	"fmt"

	"markdown.ninja/pkg/errs"
)

var (
	// Assets
	ErrAssetNotFound  = errs.NotFound("Asset not found.")
	ErrFolderNotFound = func(path string) error {
		return errs.NotFound(fmt.Sprintf("Folder not found %s", path))
	}
	ErrAssetIsTooLarge = func(maxSize int64) *errs.InvalidArgumentError {
		return errs.InvalidArgument(fmt.Sprintf("Asset is too large. Max size: %d", maxSize))
	}
	ErrPathShouldStartWithAssets         = errs.InvalidArgument("Path should start with /assets")
	ErrPathIsNotValid                    = errs.InvalidArgument("Path is not valid")
	ErrPathShouldNotFinishBySlash        = errs.InvalidArgument("Path should not finish by /")
	ErrPathIsTooDeep                     = errs.InvalidArgument("Path has too many nested folders")
	ErrAssetAlreadyExistsButIsNotAFolder = func(path string) error {
		return errs.InvalidArgument(fmt.Sprintf("%s already exists but is not a folder", path))
	}
	ErrAssetAlreadyExists = func(path string) error {
		return errs.InvalidArgument(fmt.Sprintf("%s already exists", path))
	}
	ErrAssetIsNotAFolder = func(path string) error {
		return errs.InvalidArgument(fmt.Sprintf("%s is not a folder", path))
	}
	ErrAssetIsAFolder = func(path string) error {
		return errs.InvalidArgument(fmt.Sprintf("%s is a folder", path))
	}
	ErrCantDeleteTheAssetsFolder = errs.InvalidArgument("You can't delete the /assets folder")
	ErrAssetIsNotAVideo          = errs.InvalidArgument("Asset is not a video.")
	ErrAssetNameIsNotValid       = errs.InvalidArgument("name is not valid.")

	// pages
	ErrPageTypeIsNotValid                          = errs.InvalidArgument("Page type is not valid.")
	ErrContentTypeIsNotValid                       = errs.InvalidArgument("Content type is not valid.")
	ErrPageWithPathAlreadyExists                   = errs.InvalidArgument("Page with the same URL already exists.")
	ErrPageCantBeUpdated                           = errs.InvalidArgument("Page can't be updated.")
	ErrPageNotFound                                = errs.NotFound("Page not found.")
	ErrPageBodyIsTooLarge                          = errs.InvalidArgument("Page is too large.")
	ErrPageBodyIsNotValid                          = errs.InvalidArgument("Page body is not valid.")
	ErrPageTitleIsTooLong                          = errs.InvalidArgument(fmt.Sprintf("Title is too long (max: %d characters)", PageTitleMaxSize))
	ErrPageTitleIsTooShort                         = errs.InvalidArgument(fmt.Sprintf("Title is too short (min: %d characters)", PageTitleMinSize))
	ErrPageTitleIsNotValid                         = errs.InvalidArgument("Title is not valid")
	ErrPageUrlIsNotValid                           = errs.InvalidArgument("Url is not valid.")
	ErrPageDescriptionIsTooLong                    = errs.InvalidArgument("Description is too long")
	ErrPageDescriptionIsNotValid                   = errs.InvalidArgument("Description is not valid")
	ErrPageUpdatedAtCantBeBeforeDate               = errs.InvalidArgument("Updated At can't be before page's date")
	ErrHomepageCantBeDeleted                       = errs.InvalidArgument("Homepage can't be deleted")
	ErrOnlyPostsCanBeSentAsNewsletter              = errs.InvalidArgument("Only posts can be sent as newsletter")
	ErrPageStatusIsNotValid                        = errs.InvalidArgument("status is not valid")
	ErrSendAsNewsletterCantBeUpdatedAfterBeingSent = errs.InvalidArgument("sendAsNewsletter cannot be updated after the newsletter has been sent")

	// Snippets
	ErrSnippetWithNameAlreadyExists = func(name string) error {
		return errs.InvalidArgument(fmt.Sprintf("Snippet with name: \"%s\" already exists.", name))
	}
	ErrSnippetNotFound          = errs.NotFound("Snippet not found.")
	ErrSnippetNameIsNotValid    = errs.InvalidArgument("Snippet name is not valid.")
	ErrSnippetContentIsNotValid = errs.InvalidArgument("Snippet content is not valid.")

	// Tags
	ErrTagNotFound      = errs.NotFound("Tag not found.")
	ErrTagAlreadyExists = func(name string) error {
		return errs.InvalidArgument(fmt.Sprintf("Tag \"%s\" already exists.", name))
	}
	ErrTagDescriptionIsTooLong  = errs.InvalidArgument(fmt.Sprintf("Tag description is too long (max: %d characters)", TagDescriptionMaxSize))
	ErrTagDescriptionIsNotValid = errs.InvalidArgument("Tag description is not valid")
	ErrTagNameIsTooShort        = errs.InvalidArgument(fmt.Sprintf("Tag name is too short (min: %d characters)", TagNameMinSize))
	ErrTagNameIsTooLong         = errs.InvalidArgument(fmt.Sprintf("Tag name is too long (max: %d characters)", TagNameMaxSize))
	ErrTagNameMustBeLower       = errs.InvalidArgument("Tag name must be lowercase")
	ErrTagNameIsNotValid        = errs.InvalidArgument("Tag name is not valid.")
)
