package openapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
)

func TestRegisterRoutes(t *testing.T) {
	s := httpapi.New(false)
	RegisterRoutes(s)

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v3/api-docs")
	if err != nil {
		t.Fatalf("get /v3/api-docs: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json content type, got %q", ct)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode spec: %s", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("expected non-empty paths in spec, got: %+v", doc["paths"])
	}
	if _, ok := paths["/cms/sign"]; !ok {
		t.Error("expected /cms/sign in spec paths")
	}

	resp2, err := http.Get(srv.URL + "/swagger-ui.html")
	if err != nil {
		t.Fatalf("get /swagger-ui.html: %s", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected html content type, got %q", ct)
	}
}
