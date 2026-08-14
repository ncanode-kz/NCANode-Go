package crlservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serveFile(t *testing.T, path string) *httptest.Server {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %s", path, err)
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data) //nolint:errcheck
	}))
}

func TestEnabled(t *testing.T) {
	if New(t.TempDir(), true, nil, time.Hour, nil, 0).Enabled() != true {
		t.Fatal("expected Enabled() true")
	}
	if New(t.TempDir(), false, nil, time.Hour, nil, 0).Enabled() != false {
		t.Fatal("expected Enabled() false")
	}
}

func TestBootstrapDisabled(t *testing.T) {
	svc := New(t.TempDir(), false, []string{"http://unused"}, time.Hour, nil, 0)

	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("expected no error when disabled, got %s", err)
	}

	if len(svc.FullPaths()) != 0 {
		t.Fatal("expected no cached paths when disabled")
	}
}

func TestBootstrapCachesFullAndDelta(t *testing.T) {
	full := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer full.Close()
	delta := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer delta.Close()

	dir := t.TempDir()
	svc := New(dir, true, []string{full.URL}, time.Hour, []string{delta.URL}, time.Hour)

	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %s", err)
	}

	fullPaths := svc.FullPaths()
	deltaPaths := svc.DeltaPaths()

	if len(fullPaths) != 1 || len(deltaPaths) != 1 {
		t.Fatalf("expected 1 full + 1 delta path, got %d/%d", len(fullPaths), len(deltaPaths))
	}

	for _, p := range append(append([]string{}, fullPaths...), deltaPaths...) {
		if filepath.Dir(p) != dir {
			t.Errorf("expected cached file under %s, got %s", dir, p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected cached file to exist: %s", err)
		}
	}
}

func TestBootstrapFailsOnBadURL(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()

	svc := New(t.TempDir(), true, []string{bad.URL}, time.Hour, nil, 0)

	if err := svc.Bootstrap(context.Background()); err == nil {
		t.Fatal("expected error for unreachable CRL URL")
	}
}

func TestStartBackgroundRefreshDisabled(t *testing.T) {
	svc := New(t.TempDir(), false, []string{"http://unused"}, time.Hour, nil, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.StartBackgroundRefresh(ctx) // не должно паниковать и не должно запускать горутины
}

func TestStartBackgroundRefreshWithDelta(t *testing.T) {
	full := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer full.Close()
	delta := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer delta.Close()

	svc := New(t.TempDir(), true, []string{full.URL}, time.Hour, []string{delta.URL}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartBackgroundRefresh(ctx)
}

func TestRefreshDeltaFailure(t *testing.T) {
	full := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer full.Close()

	badDelta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer badDelta.Close()

	svc := New(t.TempDir(), true, []string{full.URL}, time.Hour, []string{badDelta.URL}, time.Hour)

	if err := svc.Bootstrap(context.Background()); err == nil {
		t.Fatal("expected error when delta CRL is unreachable")
	}
	if len(svc.FullPaths()) != 1 {
		t.Fatalf("expected full crl to still be cached, got %d paths", len(svc.FullPaths()))
	}
}

func TestDownloadOneInvalidURL(t *testing.T) {
	svc := New(t.TempDir(), true, []string{"http://\x7f"}, time.Hour, nil, 0)

	if err := svc.Bootstrap(context.Background()); err == nil {
		t.Fatal("expected error for malformed url")
	}
}

func TestBackgroundRefreshKeepsOldCacheOnFailure(t *testing.T) {
	full := serveFile(t, "../testdata/certs/nca_gost2022_test.crl")
	defer full.Close()

	svc := New(t.TempDir(), true, []string{full.URL}, 20*time.Millisecond, nil, 0)

	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %s", err)
	}

	full.Close() // дальнейшие обновления будут падать

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.StartBackgroundRefresh(ctx)
	time.Sleep(60 * time.Millisecond)

	if len(svc.FullPaths()) != 1 {
		t.Fatalf("expected previous cache to be kept, got %d paths", len(svc.FullPaths()))
	}
}
