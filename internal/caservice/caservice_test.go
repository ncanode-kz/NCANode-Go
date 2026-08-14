package caservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ncanode-kz/gokalkan/ckalkan"
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

func TestBootstrapSuccess(t *testing.T) {
	root := serveFile(t, "../testdata/certs/root_test_gost_2022.cer")
	defer root.Close()
	intermediate := serveFile(t, "../testdata/certs/nca_gost2022_test.cer")
	defer intermediate.Close()

	svc := New([]string{root.URL, intermediate.URL}, time.Hour)

	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %s", err)
	}

	certs := svc.Certs()
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	if certs[0].Type != ckalkan.CertTypeCA {
		t.Errorf("expected first cert to be CA (self-signed root), got type %v", certs[0].Type)
	}
	if certs[1].Type != ckalkan.CertTypeIntermediate {
		t.Errorf("expected second cert to be Intermediate, got type %v", certs[1].Type)
	}
}

func TestBootstrapFailureOnAnyURL(t *testing.T) {
	root := serveFile(t, "../testdata/certs/root_test_gost_2022.cer")
	defer root.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer badServer.Close()

	svc := New([]string{root.URL, badServer.URL}, time.Hour)

	if err := svc.Bootstrap(context.Background()); err == nil {
		t.Fatal("expected Bootstrap to fail when one URL is unreachable")
	}

	if len(svc.Certs()) != 0 {
		t.Fatal("expected no certs to be cached after failed bootstrap")
	}
}

func TestBackgroundRefreshKeepsOldCertsOnFailure(t *testing.T) {
	root := serveFile(t, "../testdata/certs/root_test_gost_2022.cer")
	defer root.Close()

	svc := New([]string{root.URL}, 20*time.Millisecond)

	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %s", err)
	}

	root.Close() // дальнейшие обновления будут падать

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.StartBackgroundRefresh(ctx)
	time.Sleep(60 * time.Millisecond)

	if len(svc.Certs()) != 1 {
		t.Fatalf("expected previous cert set to be kept, got %d certs", len(svc.Certs()))
	}
}
