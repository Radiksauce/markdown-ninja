package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/organizations"
)

func (client *Client) GetOrganization(ctx context.Context, apiInput organizations.GetOrganizationInput) (organization organizations.Organization, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteOrganization,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &organization)

	return
}
