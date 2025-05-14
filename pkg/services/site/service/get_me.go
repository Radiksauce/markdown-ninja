package service

import (
	"context"

	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/site"
)

func (service *SiteService) GetMe(ctx context.Context, input kernel.EmptyInput) (ret *site.Contact, err error) {
	contact := service.contactsService.CurrentContact(ctx)
	if contact == nil {
		// if no user is authenticated we return null
		return
	}

	websiteContact := service.convertContact(*contact)
	ret = &websiteContact

	return ret, nil
}
