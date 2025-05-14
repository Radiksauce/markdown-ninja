package errs

import (
	"testing"
)

func TestInternalErrorNilNoPanic(t *testing.T) {
	_ = Internal("message", nil)
}
