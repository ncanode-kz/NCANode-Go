package openapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

	if strings.Contains(swaggerUIHTML, "://") {
		t.Fatal("swagger UI page must not reference any external (CDN) URL")
	}

	for _, asset := range []string{
		"/swagger-ui/swagger-ui.css",
		"/swagger-ui/swagger-ui-bundle.js",
		"/swagger-ui/swagger-ui-standalone-preset.js",
		"/swagger-ui/favicon-32x32.png",
	} {
		resp, err := http.Get(srv.URL + asset)
		if err != nil {
			t.Fatalf("get %s: %s", asset, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 for %s, got %d", asset, resp.StatusCode)
		}
	}
}
