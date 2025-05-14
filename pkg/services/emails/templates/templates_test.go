package templates

import (
	"strings"
	"testing"
)

func TestNewsletterEmailTemplate(t *testing.T) {
	if strings.TrimSpace(NewsletterEmailTemplate) == "" {
		t.Error("NewsletterEmailTemplate is empty")
	}
}
