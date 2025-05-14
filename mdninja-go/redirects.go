package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/websites"
)

func (client *Client) SaveRedirects(ctx context.Context, apiInput websites.SaveRedirectsInput) (redirects []websites.Redirect, err error) {
	redirects = make([]websites.Redirect, 0)
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteSaveRedirect,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &redirects)

	return
}
