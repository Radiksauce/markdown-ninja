package service

import (
	"context"
	"path/filepath"
	"strings"

	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/websites"
)

func (service *ContentService) ListAssets(ctx context.Context, input content.ListAssetsInput) (assets []content.Asset, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err == nil {
		err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, input.WebsiteID)
		if err != nil {
			return
		}
	} else {
		var website websites.Website
		httpCtx := httpctx.FromCtx(ctx)
		if httpCtx.ApiKey == nil {
			err = kernel.ErrPermissionDenied
			return
		}

		website, err = service.websitesService.FindWebsiteByID(ctx, service.db, input.WebsiteID)
		if err != nil {
			return
		}

		_, err = service.organizationsService.CheckCurrentApiKey(ctx, website.OrganizationID)
		if err != nil {
			return
		}
	}

	if input.Folder != nil {
		folder := strings.TrimSpace(*input.Folder)
		err = service.validateAssetFolder(folder)
		if err != nil {
			return
		}

		var assetFolder content.Asset
		fodlerParent := filepath.Dir(folder)
		fodlerName := filepath.Base(folder)

		assetFolder, err = service.repo.FindAssetByPath(ctx, service.db, input.WebsiteID, fodlerParent, fodlerName)
		if err != nil {
			if errs.IsNotFound(err) {
				err = content.ErrFolderNotFound(folder)
				return
			}
			return
		}
		if assetFolder.Type != content.AssetTypeFolder {
			err = content.ErrAssetIsNotAFolder(folder)
			return
		}

		assets, err = service.repo.FindAssetsDirectChildren(ctx, service.db, input.WebsiteID, folder)
		if err != nil {
			return
		}
	} else {
		assets, err = service.repo.FindAssetsAllChildren(ctx, service.db, input.WebsiteID, "/assets")
		if err != nil {
			return
		}
	}
	return
}
