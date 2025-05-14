package service

import (
	"fmt"
	"net/mail"

	"markdown.ninja/pkg/services/websites"
)

func (service *EmailsService) GetDefaultFromAddressForWebsite(website websites.Website) mail.Address {
	return mail.Address{
		Name:    website.Name,
		Address: fmt.Sprintf("noreply@%s", service.httpConfig.WebsitesRootDomain),
	}
}
