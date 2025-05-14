package mdninja

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"markdown.ninja/pkg/server/api"
	"markdown.ninja/pkg/server/apiutil"
	"markdown.ninja/pkg/services/content"
)

func (client *Client) UploadAsset(ctx context.Context, input content.UploadAssetInput) (asset content.Asset, err error) {
	url := client.apiBaseUrl + api.RouteUploadAsset

	// TODO: the asset is currently entierly read in memory before being sent. A stream approach is needed
	// maybe with io.Pipe
	var bodyBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&bodyBuffer)

	fileWriter, err := multipartWriter.CreateFormFile("file", input.Name)
	if err != nil {
		return
	}

	_, err = io.Copy(fileWriter, input.Data)
	if err != nil {
		return
	}

	websiteIdFieldWriter, err := multipartWriter.CreateFormField("website_id")
	if err != nil {
		return
	}
	_, err = websiteIdFieldWriter.Write([]byte(input.WebsiteID.String()))
	if err != nil {
		return
	}

	if input.Folder != nil {
		var folderFieldWriter io.Writer
		folderFieldWriter, err = multipartWriter.CreateFormField("folder")
		if err != nil {
			return
		}
		_, err = folderFieldWriter.Write([]byte(*input.Folder))
		if err != nil {
			return
		}
	}

	if input.ProductID != nil {
		var productIDFieldWriter io.Writer
		productIDFieldWriter, err = multipartWriter.CreateFormField("product_id")
		if err != nil {
			return
		}
		_, err = productIDFieldWriter.Write([]byte(input.ProductID.String()))
		if err != nil {
			return
		}
	}

	multipartWriter.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &bodyBuffer)
	if err != nil {
		return
	}

	req.Header.Add("User-Agent", UserAgent)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	req.Header.Add("Authorization", "ApiKey "+client.apiKey)

	res, err := client.httpClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return
	}

	if res.StatusCode >= 400 {
		var apiErr apiutil.ApiError
		err = json.Unmarshal(body, &apiErr)
		if err != nil {
			err = fmt.Errorf("decoding API response: %w", err)
			return
		}
		err = errors.New(apiErr.Message)
		return
	}

	err = json.Unmarshal(body, &asset)
	if err != nil {
		err = fmt.Errorf("decoding API response: %w", err)
		return
	}

	return
}
