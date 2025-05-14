package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/store"
)

func (client *Client) GetProduct(ctx context.Context, apiInput store.GetProductInput) (product store.Product, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteProduct,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &product)

	return
}

func (client *Client) UpdateProduct(ctx context.Context, apiInput store.UpdateProductInput) (product store.Product, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteUpdateProduct,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &product)

	return
}
