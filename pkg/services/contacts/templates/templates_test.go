package templates

import (
	"strings"
	"testing"
)

func TestVerifyEmailEmailTemplate(t *testing.T) {
	if strings.TrimSpace(VerifyEmailEmailTemplate) == "" {
		t.Error("VerifyEmailEmailTemplate is empty")
	}
}
