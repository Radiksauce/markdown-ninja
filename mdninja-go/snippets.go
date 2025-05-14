package mdninja

import (
	"context"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/services/content"
	"markdown.ninja/pkg/services/kernel"
)

func (client *Client) CreateSnippet(ctx context.Context, apiInput content.CreateSnippetInput) (snippet content.Snippet, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteCreateSnippet,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &snippet)

	return
}

func (client *Client) UpdateSnippet(ctx context.Context, apiInput content.UpdateSnippetInput) (snippet content.Snippet, err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteUpdateSnippet,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &snippet)

	return
}

func (client *Client) ListSnippets(ctx context.Context, apiInput content.ListSnippetsInput) (ret kernel.PaginatedResult[content.Snippet], err error) {
	req := requestParams{
		Method:  http.MethodPost,
		Route:   api.RouteSnippets,
		Payload: apiInput,
	}

	err = client.request(ctx, req, &ret)

	return
}
