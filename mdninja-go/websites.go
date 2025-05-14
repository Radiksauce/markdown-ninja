package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/websites"
)

func (client *Client) FetchWebsite(ctx context.Context, apiInput websites.GetWebsiteInput) (website websites.Website, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteWebsite,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &website)

	return
}

func (client *Client) UpdateWebsite(ctx context.Context, apiInput websites.UpdateWebsiteInput) (website websites.Website, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteUpdateWebsite,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &website)

	return
}

func (client *Client) GetWebsitesForOrganization(ctx context.Context, apiInput websites.GetWebsitesForOrganizationInput) (res []websites.Website, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteWebsites,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &res)

	return
}
