// Package testutil - общие тестовые хелперы для internal/service/* и
// internal/certservice: поднимает App с локальными тестовыми фикстурами
// (без обращения к реальной сети), пригодный для sign/verify тестов.
package testutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/caservice"
	"github.com/ncanode-kz/NCANode-Go/internal/config"
	"github.com/ncanode-kz/NCANode-Go/internal/crlservice"
	"github.com/ncanode-kz/NCANode-Go/internal/ocspservice"
)

const TestCertPassword = "Qwerty12"

const (
	fixtureRootCA       = "root_test_gost_2022.cer"
	fixtureIntermediate = "nca_gost2022_test.cer"
	fixtureCRL          = "nca_gost2022_test.crl"
)

// certsDir - абсолютный путь до internal/testdata/certs, вычисленный от
// расположения этого файла (а не от cwd вызывающего теста - testutil зовут
// из пакетов на разной глубине вложенности, относительный путь был бы разным
// для каждого).
//
//nolint:gochecknoglobals
var certsDir = func() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "testdata", "certs")
}()

func fixturePath(name string) string {
	return filepath.Join(certsDir, name)
}

func serveFixture(t *testing.T, name string) *httptest.Server {
	t.Helper()

	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture %s: %s", name, err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	return srv
}

// NewApp собирает *app.App поверх локальных тестовых фикстур (CA-цепочка и
// CRL раздаются через httptest, без внешней сети) и настроенных на
// test.pki.gov.kz TSP/OCSP URL (эти два всё ещё требуют сети - используются
// только в тестах, помеченных build tag "oracle" или явно бьющих в TSP/OCSP).
func NewApp(t *testing.T) *app.App {
	t.Helper()

	rootSrv := serveFixture(t, fixtureRootCA)
	intermediateSrv := serveFixture(t, fixtureIntermediate)
	crlSrv := serveFixture(t, fixtureCRL)

	ca := caservice.New([]string{rootSrv.URL, intermediateSrv.URL}, time.Hour)
	if err := ca.Bootstrap(context.Background()); err != nil {
		t.Fatalf("ca bootstrap: %s", err)
	}

	crl := crlservice.New(t.TempDir(), true, []string{crlSrv.URL}, time.Hour, nil, 0)
	if err := crl.Bootstrap(context.Background()); err != nil {
		t.Fatalf("crl bootstrap: %s", err)
	}

	ocsp := ocspservice.New("http://test.pki.gov.kz/ocsp/")

	cfg := config.Config{TSP: config.TSPConfig{URL: "http://test.pki.gov.kz/tsp/"}}

	a, err := app.New(cfg, ca, crl, ocsp)
	if err != nil {
		t.Fatalf("app.New: %s", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	return a
}

// ReadFixture читает файл теста из internal/testdata/certs.
func ReadFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf("read fixture %s: %s", name, err)
	}

	return data
}
