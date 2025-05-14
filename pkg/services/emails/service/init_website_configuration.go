package service

import (
	"context"
	"time"

	"github.com/bloom42/stdx-go/db"
	"github.com/bloom42/stdx-go/guid"
	"markdown.ninja/pkg/mailer"
	"markdown.ninja/pkg/services/emails"
)

func (service *EmailsService) InitWebsiteConfiguration(ctx context.Context, db db.Queryer, websiteID guid.GUID, name string) (configuration emails.WebsiteConfiguration, err error) {
	now := time.Now().UTC()
	configuration = emails.WebsiteConfiguration{
		CreatedAt:      now,
		UpdatedAt:      now,
		FromName:       name,
		FromAddress:    "",
		FromDomain:     "",
		DnsRecords:     []mailer.DnsRecord{},
		DomainVerified: false,
		WebsiteID:      websiteID,
	}

	err = service.repo.CreateWebsiteConfiguration(ctx, db, configuration)
	if err != nil {
		return
	}

	return
}
