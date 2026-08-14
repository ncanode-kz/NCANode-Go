package ocspservice

import "testing"

func TestURL(t *testing.T) {
	s := New("http://example.test/ocsp")
	if s.URL() != "http://example.test/ocsp" {
		t.Errorf("unexpected URL: %q", s.URL())
	}
}
