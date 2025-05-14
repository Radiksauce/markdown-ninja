package service

import (
	"context"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

// DetectMimeType always returns a valid MIME type: if it cannot determine a more specific one, it returns "application/octet-stream".
// if data is null then we use the file name extension to infer the mime type
func (service *ContentService) DetectMimeType(ctx context.Context, filename string, data []byte) (mimeType string) {
	mimeType = "application/octet-stream"

	if data != nil {
		mimeType = http.DetectContentType(data)
	}

	if mimeType == "application/octet-stream" || strings.HasPrefix(mimeType, "text/plain") {
		extension := filepath.Ext(filename)
		mimeTypeByExtension := mime.TypeByExtension(extension)
		if mimeTypeByExtension != "" {
			mimeType = mimeTypeByExtension
		}
	}
	return
}
