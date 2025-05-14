package service

import (
	"context"
	"strings"
	"time"

	"markdown.ninja/pkg/errs"
	"markdown.ninja/pkg/server/httpctx"
	"markdown.ninja/pkg/services/kernel"
	"markdown.ninja/pkg/services/organizations"
	"markdown.ninja/pkg/services/websites"
)

func (service *WebsitesService) UpdateWebsite(ctx context.Context, input websites.UpdateWebsiteInput) (website websites.Website, err error) {
	httpCtx := httpctx.FromCtx(ctx)

	isAdmin := false

	actorID, err := service.kernel.CurrentUserID(ctx)
	if err == nil {
		website, err = service.repo.FindWebsiteByID(ctx, service.db, input.ID, false)
		if err != nil {
			return
		}

		_, err = service.organizationsService.CheckUserIsStaff(ctx, service.db, actorID, website.OrganizationID)
		if err != nil {
			return
		}

		isAdmin = httpCtx.AccessToken.IsAdmin
	} else {
		if httpCtx.ApiKey == nil {
			err = kernel.ErrPermissionDenied
			return
		}

		website, err = service.repo.FindWebsiteByID(ctx, service.db, input.ID, false)
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
		website.Name = strings.TrimSpace(*input.Name)
		err = validateWebsiteName(website.Name)
		if err != nil {
			return
		}
	}

	if input.Description != nil {
		description := strings.TrimSpace(*input.Description)
		err = validateWebsiteDescription(description)
		if err != nil {
			return
		}
		website.Description = description
	}

	if input.Header != nil {
		website.Header = strings.TrimSpace(*input.Header)
		err = validateWebsiteHeader(website.Header)
		if err != nil {
			return
		}
	}

	if input.Footer != nil {
		website.Footer = strings.TrimSpace(*input.Footer)
		err = validateWebsiteFooter(website.Footer)
		if err != nil {
			return
		}
	}

	if input.Navigation != nil {
		// TODO: validate
		website.Navigation = *input.Navigation
		if website.Navigation.Primary == nil {
			website.Navigation.Primary = []websites.WebsiteNavigationItem{}
		}
		if website.Navigation.Secondary == nil {
			website.Navigation.Secondary = []websites.WebsiteNavigationItem{}
		}
		err = validateWebsiteNavigation(&website.Navigation)
		if err != nil {
			return
		}
	}

	if input.Slug != nil {
		var existingWebsiteWithSlug websites.Website

		website.Slug = strings.TrimSpace(*input.Slug)
		err = validateWebsiteSlug(website.Slug, isAdmin)
		if err != nil {
			return
		}

		// check if another website is already using this slug
		existingWebsiteWithSlug, err = service.repo.FindWebsiteBySlug(ctx, service.db, website.Slug)
		if err == nil && !existingWebsiteWithSlug.ID.Equal(website.ID) {
			err = websites.ErrWebsiteSlugNotAvailable
			return
		} else {
			if errs.IsNotFound(err) {
				err = nil
			}
		}
		if err != nil {
			return
		}

		if strings.HasSuffix(website.PrimaryDomain, service.websitesRootDomain) {
			website.PrimaryDomain = service.getSubdomainForSlug(website.Slug)
		}
	}

	if input.RobotsTxt != nil {
		err = validateRobotsTxt(*input.RobotsTxt)
		if err != nil {
			return
		}
		website.RobotsTxt = *input.RobotsTxt
	}

	if input.Blocked != nil {
		if !isAdmin {
			err = kernel.ErrPermissionDenied
			return
		}
		if *input.Blocked {
			if website.BlockedAt == nil {
				website.BlockedAt = &now
			}
		} else {
			if website.BlockedAt != nil {
				website.BlockedAt = nil
				website.BlockedReason = ""
			}
		}
	}

	if input.Currency != nil {
		err = validateCurrency(*input.Currency)
		if err != nil {
			return
		}
		website.Currency = *input.Currency
	}

	if input.AccentColor != nil {
		err = service.kernel.ValidateColor(*input.AccentColor)
		if err != nil {
			return
		}
		website.Colors.Accent = *input.AccentColor
		// website.Colors.ButtonsBackground = *input.AccentColor
		// website.Colors.Links = *input.AccentColor

		// // below is a small algorithm to set the buttons' text color with enough contrast
		// accentColorInt, err = strconv.ParseInt(strings.TrimPrefix(*input.AccentColor, "#"), 16, 32)
		// if err != nil {
		// 	err = fmt.Errorf("websites.UpdateWebsite: parsing accent color to int: %w", err)
		// 	return
		// }

		// if (uint8(accentColorInt) > 220) &&
		// 	(uint8(accentColorInt>>8) > 220) &&
		// 	(uint8(accentColorInt>>16) > 220) {
		// 	website.Colors.ButtonsText = "#000000"
		// } else {
		// 	website.Colors.ButtonsText = "#ffffff"
		// }
	}

	if input.BackgroundColor != nil {
		err = service.kernel.ValidateColor(*input.BackgroundColor)
		if err != nil {
			return
		}
		website.Colors.Background = *input.BackgroundColor
		// website.Colors.ButtonsText = *input.BackgroundColor
	}

	if input.TextColor != nil {
		err = service.kernel.ValidateColor(*input.TextColor)
		if err != nil {
			return
		}
		website.Colors.Text = *input.TextColor
		// website.Colors.Headings = *input.TextColor
	}

	if input.Theme != nil {
		err = validateTheme(*input.Theme)
		if err != nil {
			return
		}
		website.Theme = *input.Theme
	}

	if input.Ad != nil {
		ad := strings.TrimSpace(*input.Ad)
		if ad == "" {
			website.Ad = nil
		} else {
			err = validateAd(*input.Ad)
			if err != nil {
				return
			}
			website.Ad = input.Ad
		}
	}

	if input.Announcement != nil {
		announcement := strings.TrimSpace(*input.Announcement)
		if announcement == "" {
			website.Announcement = nil
		} else {
			err = validateAnnouncement(announcement)
			if err != nil {
				return
			}
			website.Announcement = input.Announcement
		}
	}

	if input.Logo != nil {
		logoUrl := strings.TrimSpace(*input.Logo)
		if logoUrl == "" {
			website.Logo = nil
		} else {
			err = validateWebsiteLogo(logoUrl)
			if err != nil {
				return
			}
			website.Logo = input.Logo
		}
	}

	if input.PoweredBy != nil {
		website.PoweredBy = *input.PoweredBy
	}

	err = service.organizationsService.CheckBillingGatedAction(ctx, service.db, website.OrganizationID, organizations.BillingGatedActionUpdateWebsite{
		PoweredBy: website.PoweredBy,
		Ad:        website.Ad,
	})
	if err != nil {
		return
	}

	website.UpdatedAt = now
	website.ModifiedAt = now

	err = service.repo.UpdateWebsite(ctx, service.db, website)
	if err != nil {
		return
	}

	return
}
