package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/content"
)

func (client *Client) DeleteAsset(ctx context.Context, apiInput content.DeleteAssetInput) (err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteDeleteAsset,
		Payload: apiInput,
	}

	err = client.request(ctx, req, nil)

	return
}

func (client *Client) ListAssets(ctx context.Context, apiInput content.ListAssetsInput) (assets []content.Asset, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteAssets,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &assets)

	return
}
