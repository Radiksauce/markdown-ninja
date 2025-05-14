package templates

import (
	"strings"
	"testing"
)

func TestVideoIframeTemplate(t *testing.T) {
	if strings.TrimSpace(VideoIframeTemplate) == "" {
		t.Error("VideoIframeTemplate is empty")
	}
}
