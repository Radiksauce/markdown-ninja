package service

import (
	"context"
	"math"
	"strings"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/contacts"
	"markdown.ninja/pkg/services/kernel"
)

func (service *ContactsService) ListContacts(ctx context.Context, input contacts.ListContactsInput) (ret kernel.PaginatedResult[contacts.Contact], err error) {
	httpCtx := httpctx.FromCtx(ctx)

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err != nil {
		return
	}

	if !httpCtx.AccessToken.IsAdmin {
		err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
		if err != nil {
			return
		}
	}

	limit := int64(math.MaxInt64)
	searchQuery := strings.TrimSpace(input.Query)

	ret.Data, err = service.repo.FindVerifiedContactsForWebsite(ctx, service.db, input.WebsiteID, searchQuery, limit)
	return
}
