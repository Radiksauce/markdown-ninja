package service

import (
	"context"
	"strings"
	"time"

	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/store"
	"markdown.ninja/pkg/services/websites"
)

func (service *StoreService) UpdateProduct(ctx context.Context, input store.UpdateProductInput) (product store.Product, err error) {
	actorID, err := service.kernel.CurrentUserID(ctx)
	if err == nil {
		product, err = service.repo.FindProductByID(ctx, service.db, input.ID)
		if err != nil {
			return
		}

		err = service.websitesService.CheckUserIsStaff(ctx, service.db, actorID, product.WebsiteID)
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

		product, err = service.repo.FindProductByID(ctx, service.db, input.ID)
		if err != nil {
			return
		}

		website, err = service.websitesService.FindWebsiteByID(ctx, service.db, product.WebsiteID)
		if err != nil {
			return
		}

		_, err = service.organizationsService.CheckCurrentApiKey(ctx, website.OrganizationID)
		if err != nil {
			return
		}
	}

	now := time.Now().UTC()

	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		err = service.validateProductName(name)
		if err != nil {
			return
		}
		product.Name = name
	}

	if input.Description != nil {
		description := strings.TrimSpace(*input.Description)
		err = service.validateProductDescription(description)
		if err != nil {
			return
		}
		product.Description = description
	}

	if input.Price != nil {
		price := *input.Price
		err = service.validateProductPrice(price)
		if err != nil {
			return
		}
		product.Price = price
	}

	if input.Status != nil {
		product.Status = *input.Status
	}

	product.UpdatedAt = now
	err = service.repo.UpdateProduct(ctx, service.db, product)
	if err != nil {
		return
	}

	err = service.hydrateProduct(ctx, service.db, &product)
	if err != nil {
		return
	}

	return
}
