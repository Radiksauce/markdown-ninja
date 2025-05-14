package pingoo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bloom42/stdx-go/httpx"
	"github.com/bloom42/stdx-go/uuid"
	"github.com/klauspost/compress/zstd"
)

const userAgent = "Pingoo/GoSDK (https://pingoo.io)"

type ClientConfig struct {
	Url        *string
	HttpClient *http.Client
	Logger     *slog.Logger
}

type Client struct {
	pingooURL  string
	projectId  uuid.UUID
	apiKey     string
	apiBaseUrl string
	httpClient *http.Client
	logger     *slog.Logger

	jwksFetchInterval time.Duration
	// a map of verifying keys, by KeyID
	jwksKeys     map[string]VerifyingKey
	jwksKeysLock sync.RWMutex
}

type ApiError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (err ApiError) Error() string {
	return err.Message
}

// TODO: wrap errors with errs
func NewClient(apiKey string, projectID string, config *ClientConfig) (client *Client, err error) {
	url := "https://pingoo.io"
	httpClient := httpx.DefaultClient()

	if config != nil {
		if config.Url != nil && *config.Url != "" {
			url = *config.Url
		}
		if config.HttpClient != nil {
			httpClient = config.HttpClient
		}
	}

	projectId, err := uuid.Parse(projectID)
	if err != nil {
		return nil, errors.New("pingoo: projectID is not valid")
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	client = &Client{
		pingooURL:         url,
		apiBaseUrl:        url + "/api",
		projectId:         projectId,
		apiKey:            apiKey,
		httpClient:        httpClient,
		logger:            logger,
		jwksFetchInterval: time.Minute,
		jwksKeys:          make(map[string]VerifyingKey),
		jwksKeysLock:      sync.RWMutex{},
	}
	go client.periodicallyFetchJkws()
	return client, nil
}

type requestParams struct {
	Method  string
	Route   string
	Payload any
}

func (client *Client) request(ctx context.Context, params requestParams, dst any) error {
	url := client.apiBaseUrl + params.Route

	req, err := http.NewRequestWithContext(ctx, params.Method, url, nil)
	if err != nil {
		return err
	}

	if params.Payload != nil {
		jsonPayload, err := json.Marshal(params.Payload)
		if err != nil {
			return fmt.Errorf("client.request: marshaling JSON: %w", err)
		}

		// zstdCompressor, err := zstd.NewWriter(nil,
		// 	zstd.WithEncoderCRC(true),
		// 	zstd.WithEncoderConcurrency(1),
		// )
		// if err != nil {
		// 	return fmt.Errorf("client.request: error instantiating zstd encoder: %w", err)
		// }

		// compressedPayload := zstdCompressor.EncodeAll(jsonPayload, nil)
		// zstdCompressor.Close()

		// req.Body = io.NopCloser(bytes.NewReader(compressedPayload))
		req.Body = io.NopCloser(bytes.NewReader(jsonPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "zstd")
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "zstd")
	req.Header.Set("Authorization", "ApiKey "+client.apiKey)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("client.request: Doing HTTP request: %w", err)
	}
	defer res.Body.Close()

	var body []byte

	resContentEncoding := res.Header.Get("Content-Encoding")
	if resContentEncoding != "" {
		if resContentEncoding != "zstd" {
			return fmt.Errorf("client.request: Content-Encoding \"%s\" not supported. Only zstd is currently supported", resContentEncoding)
		}

		bodyBuffer := bytes.NewBuffer(make([]byte, 0, 1000))

		zstdDecompressor, err := zstd.NewReader(res.Body,
			zstd.WithDecoderConcurrency(1),
		)
		if err != nil {
			return fmt.Errorf("client.request: error instantiating zstd encoder: %w", err)
		}

		_, err = io.Copy(bodyBuffer, zstdDecompressor)
		if err != nil {
			zstdDecompressor.Close()
			return fmt.Errorf("client.request: error decompressing response's body: %w", err)
		}
		zstdDecompressor.Close()
		body = bodyBuffer.Bytes()
	} else {
		body, err = io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("client.request: Reading body: %w", err)
		}
	}

	if res.StatusCode >= 400 {
		var apiErr ApiError
		err = json.Unmarshal(body, &apiErr)
		if err != nil {
			return fmt.Errorf("pingoo: error decoding API response: %w", err)
		}
		return apiErr
	}

	if dst != nil {
		err = json.Unmarshal(body, &dst)
		if err != nil {
			return fmt.Errorf("pingoo: error decoding API response: %w", err)
		}
	}

	return nil
}
