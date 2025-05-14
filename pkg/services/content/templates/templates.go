package templates

import (
	_ "embed"
)

//go:embed video_iframe.html
var VideoIframeTemplate string

type VideoIframeTemplateData struct {
	VideoUrl string
}
