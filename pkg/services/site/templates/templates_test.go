package templates

import (
	"strings"
	"testing"
)

func TestLoginEmailTemplate(t *testing.T) {
	if strings.TrimSpace(LoginEmailTemplate) == "" {
		t.Error("LoginEmailTemplate is empty")
	}
}

func TestSubscribeEmailTemplate(t *testing.T) {
	if strings.TrimSpace(SubscribeEmailTemplate) == "" {
		t.Error("SubscribeEmailTemplate is empty")
	}
}
