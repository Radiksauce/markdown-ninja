package client

import (
	"log/slog"

	"github.com/microcosm-cc/bluemonday"
	"markdown.ninja/mdninja-go"
)

type Client struct {
	logger       *slog.Logger
	apiClient    *mdninja.Client
	htmlStripper *bluemonday.Policy
}

func New(markdownNinjaUrl, apiKey string, logger *slog.Logger) (client *Client, err error) {
	apiClient, err := mdninja.NewClient(markdownNinjaUrl, apiKey)
	if err != nil {
		return
	}

	client = &Client{
		logger:       logger,
		apiClient:    apiClient,
		htmlStripper: bluemonday.StrictPolicy(),
	}
	return
}
