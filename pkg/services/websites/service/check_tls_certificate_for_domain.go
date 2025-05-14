package service

import (
	"context"
	"time"

	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) CheckTlsCertificateForDomain(ctx context.Context, input websites.CheckTlsCertificateForDomainInput) (err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	domain, err := service.repo.FindDomainByID(ctx, service.db, input.DomainID)
	if err != nil {
		return
	}

	website, err := service.repo.FindWebsiteByID(ctx, service.db, domain.WebsiteID, false)
	if err != nil {
		return
	}

	_, err = service.organizationsService.CheckUserIsStaff(ctx, service.db, actorID, website.OrganizationID)
	if err != nil {
		return
	}

	if domain.TlsActive {
		return
	}

	// err = service.cdn.GetCertificate(ctx, *domain.CdnDomainID)
	// if err != nil {
	// 	errMessage := "websites.CheckTlsCertificateForDomain: Getting certificate"
	// 	logger.Warn(errMessage, slogx.Err(err))
	// 	err = websites.ErrGettingTlsCertificate
	// 	return
	// }

	now := time.Now().UTC()
	domain.UpdatedAt = now
	domain.TlsActive = true
	err = service.repo.UpdateDomain(ctx, service.db, domain)
	if err != nil {
		return
	}

	return
}
