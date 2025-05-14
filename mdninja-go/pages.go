package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/kernel"
)

func (client *Client) CreatePage(ctx context.Context, input content.CreatePageInput) (page content.Page, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteCreatePage,
		Payload: input,
	}

	err = client.request(ctx, req, &page)
	return
}

func (client *Client) UpdatePage(ctx context.Context, input content.UpdatePageInput) (page content.Page, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteUpdatePage,
		Payload: input,
	}

	err = client.request(ctx, req, &page)
	return
}

func (client *Client) DeletePage(ctx context.Context, input content.DeletePageInput) (err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteDeletePage,
		Payload: input,
	}

	err = client.request(ctx, req, nil)
	return
}

func (client *Client) ListPages(ctx context.Context, input content.ListPagesInput) (res kernel.PaginatedResult[content.PageMetadata], err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RoutePages,
		Payload: input,
	}

	err = client.request(ctx, req, &res)
	return
}

func (client *Client) ListPosts(ctx context.Context, input content.ListPagesInput) (res kernel.PaginatedResult[content.PageMetadata], err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RoutePosts,
		Payload: input,
	}

	err = client.request(ctx, req, &res)
	return
}
