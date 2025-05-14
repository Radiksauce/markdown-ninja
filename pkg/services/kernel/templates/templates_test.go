package templates

import (
	"strings"
	"testing"
)

func TestSignupEmailTemplate(t *testing.T) {
	if strings.TrimSpace(SignupEmailTemplate) == "" {
		t.Error("SignupEmailTemplate is empty")
	}
}

func TestLoginAlertEmailTemplate(t *testing.T) {
	if strings.TrimSpace(LoginAlertEmailTemplate) == "" {
		t.Error("LoginAlertEmailTemplate is empty")
	}
}
