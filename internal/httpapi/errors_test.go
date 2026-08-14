package httpapi

import (
	"errors"
	"testing"
)

func TestAppErrorInterface(t *testing.T) {
	cause := errors.New("root cause")
	err := ClientError("bad request", cause)

	if err.Error() != "bad request" {
		t.Fatalf("Error() = %q, want %q", err.Error(), "bad request")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected errors.Is to unwrap to cause")
	}
}
