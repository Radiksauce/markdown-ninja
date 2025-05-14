package service

import (
	"context"
	"math"
	"strings"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) ListWebsites(ctx context.Context, input websites.ListWebsitesInput) (ret kernel.PaginatedResult[websites.Website], err error) {
	httpCtx := httpctx.FromCtx(ctx)

	_, err = service.kernel.CurrentUserID(ctx)
	if err != nil {
		return ret, err
	}

	if !httpCtx.AccessToken.IsAdmin {
		service.kernel.SleepAuth()
		return ret, kernel.ErrPermissionDenied
	}

	limit := int64(math.MaxInt64)

	searchQuery := strings.TrimSpace(input.Query)
	if searchQuery != "" {
		ret.Data, err = service.repo.SearchWebsites(ctx, service.db, searchQuery, limit)
		return
	}

	ret.Data, err = service.repo.FindWebsites(ctx, service.db, limit)
	return
}
