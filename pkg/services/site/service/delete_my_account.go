package service

import (
	"context"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
)

func (service *SiteService) DeleteMyAccount(ctx context.Context, _ kernel.EmptyInput) (err error) {
	contact := service.contactsService.CurrentContact(ctx)
	if contact == nil {
		return kernel.ErrAuthenticationRequired
	}

	err = service.contactsService.DeleteContactInternal(ctx, service.db, contact.ID, contact.WebsiteID)
	if err != nil {
		return err
	}

	httpCtx := httpctx.FromCtx(ctx)
	logoutCookie := service.contactsService.GenerateLogoutCookie()
	httpCtx.Response.Cookies = append(httpCtx.Response.Cookies, logoutCookie)

	return nil
}
