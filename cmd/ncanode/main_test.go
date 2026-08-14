package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ncanode-kz/NCANode-Go/internal/config"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func serveFixtureFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %s", path, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

func TestBootstrapCASuccess(t *testing.T) {
	cfg := config.Config{
		CA: config.CAConfig{
			URLs: []string{
				serveFixtureFile(t, "../../internal/testdata/certs/root_test_gost_2022.cer"),
				serveFixtureFile(t, "../../internal/testdata/certs/nca_gost2022_test.cer"),
			},
			TTL: time.Hour,
		},
	}

	ca, err := bootstrapCA(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bootstrapCA: %s", err)
	}
	if len(ca.Certs()) == 0 {
		t.Fatal("expected certs to be loaded")
	}
}

func TestBootstrapCAFailure(t *testing.T) {
	cfg := config.Config{
		CA: config.CAConfig{URLs: []string{"http://127.0.0.1:1"}, TTL: time.Hour},
	}

	if _, err := bootstrapCA(context.Background(), cfg); err == nil {
		t.Fatal("expected error for unreachable CA URL")
	}
}

func TestBootstrapCRL(t *testing.T) {
	cfg := config.Config{
		CacheDir: t.TempDir(),
		CRL: config.CRLConfig{
			Enabled: true,
			URLs:    []string{serveFixtureFile(t, "../../internal/testdata/certs/nca_gost2022_test.crl")},
			TTL:     time.Hour,
		},
	}

	crl := bootstrapCRL(context.Background(), cfg)
	if crl == nil {
		t.Fatal("expected non-nil crl service")
	}
	if len(crl.FullPaths()) == 0 {
		t.Fatal("expected crl to be cached")
	}
}

func TestNewHandlerHealth(t *testing.T) {
	a := testutil.NewApp(t)

	srv := httptest.NewServer(newHandler(a, false))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/actuator/health")
	if err != nil {
		t.Fatalf("get: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
