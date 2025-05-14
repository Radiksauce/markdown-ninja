package client

import (
	"context"
	"fmt"

	"markdown.ninja/pkg/services/websites"
)

// type localFile struct {
// 	Name         string
// 	Extension    string
// 	Path         string
// 	RelativePath string
// 	ModTime      time.Time
// 	ContentType  content.PageType
// 	MarkdownFile *markdownFile
// 	PageMetadata *content.PageMetadata
// }

func (client *Client) publishWebsite(ctx context.Context, websiteDomain string, input PublishInput, config config) error {
	listWebsitesApiInput := websites.GetWebsitesForOrganizationInput{}
	res, err := client.apiClient.GetWebsitesForOrganization(ctx, listWebsitesApiInput)
	if err != nil {
		return fmt.Errorf("publish: Fetching websites: %w", err)
	}

	var websiteExists bool
	var website websites.Website
	for _, websiteFromApi := range res {
		if websiteFromApi.PrimaryDomain == websiteDomain {
			website = websiteFromApi
			websiteExists = true
			break
		}
	}
	if !websiteExists {
		return fmt.Errorf("no website found for domain: %s", websiteDomain)
	}

	updateSiteApiInput := websites.UpdateWebsiteInput{
		ID:           website.ID,
		Navigation:   config.Navigation,
		Name:         config.Name,
		Description:  config.Description,
		Header:       config.Header,
		Footer:       config.Footer,
		Ad:           config.Ad,
		Announcement: config.Announcement,
	}
	website, err = client.apiClient.UpdateWebsite(ctx, updateSiteApiInput)
	if err != nil {
		return fmt.Errorf("publish: Updating site: %w", err)
	}

	client.logger.Info("Website successfully updated")

	if config.Redirects != nil {
		saveRedirectsApiInput := websites.SaveRedirectsInput{
			WebsiteID: website.ID,
			Redirects: config.Redirects,
		}
		_, err = client.apiClient.SaveRedirects(ctx, saveRedirectsApiInput)
		if err != nil {
			return fmt.Errorf("publish: Saving redirects: %w", err)
		}
		client.logger.Info("Redirects successfully updated")
	}

	// assets and snippets need to be updated before pages to avoid rendering a page with missing assets
	errAssets := client.uploadWebsiteAssets(ctx, website.ID, false)
	if errAssets != nil {
		client.logger.Error(errAssets.Error())
	}

	errSnippets := client.updateSnippets(ctx, website.ID)
	if errSnippets != nil {
		client.logger.Error(errSnippets.Error())
	}

	errPages := client.uploadPages(ctx, website.ID, config.PageDirs)
	if errPages != nil {
		client.logger.Error(errPages.Error())
	}

	return nil
}
