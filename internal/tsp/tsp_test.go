package tsp

import "testing"

func TestExtractMalformed(t *testing.T) {
	if _, err := Extract([]byte("not asn1")); err == nil {
		t.Error("expected error for garbage input")
	}

	if _, err := Extract(nil); err == nil {
		t.Error("expected error for empty input")
	}
}
