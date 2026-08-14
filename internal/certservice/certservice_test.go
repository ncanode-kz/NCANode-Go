package certservice

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ncanode-kz/NCANode-Go/internal/crlservice"
	"github.com/ncanode-kz/gokalkan"
	"github.com/ncanode-kz/gokalkan/ckalkan"
)

const testCertPassword = "Qwerty12"

func newTestClient(t *testing.T) *gokalkan.Client {
	t.Helper()

	certs := []gokalkan.OptionsCert{
		loadTestCACert(t, "../testdata/certs/root_test_gost_2022.cer", ckalkan.CertTypeCA),
		loadTestCACert(t, "../testdata/certs/nca_gost2022_test.cer", ckalkan.CertTypeIntermediate),
	}

	cli, err := gokalkan.NewClient(
		gokalkan.WithTSP("http://test.pki.gov.kz/tsp/"),
		gokalkan.WithOCSP("http://test.pki.gov.kz/ocsp/"),
		gokalkan.WithCerts(certs),
	)
	if err != nil {
		t.Fatalf("new client: %s", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	return cli
}

func loadTestCACert(t *testing.T, path string, typ ckalkan.CertType) gokalkan.OptionsCert {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %s", path, err)
	}

	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %s", path, err)
	}

	return gokalkan.OptionsCert{Cert: cert, Type: typ}
}

func exportCert(t *testing.T, cli *gokalkan.Client, p12Path string) string {
	t.Helper()

	key, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read %s: %s", p12Path, err)
	}

	if err := cli.LoadKeyStoreFromBytes(key, testCertPassword); err != nil {
		t.Fatalf("load key store: %s", err)
	}

	cert, err := cli.X509ExportCertificateFromStore("")
	if err != nil {
		t.Fatalf("export cert: %s", err)
	}

	return cert
}

func TestBuildIndividualValid(t *testing.T) {
	cli := newTestClient(t)
	cert := exportCert(t, cli, "../testdata/certs/individual/valid/individual_valid.p12")

	info, err := Build(cli, nil, cert, true, false)
	if err != nil {
		t.Fatalf("Build: %s", err)
	}

	if !info.Valid {
		t.Errorf("expected valid=true, revocations=%+v", info.Revocations)
	}
	if info.KeyUsage != "SIGN" {
		t.Errorf("expected keyUsage=SIGN, got %q", info.KeyUsage)
	}
	if len(info.KeyUser) != 1 || info.KeyUser[0] != "INDIVIDUAL" {
		t.Errorf("expected keyUser=[INDIVIDUAL], got %v", info.KeyUser)
	}
	if info.Subject.IIN != "123456789011" {
		t.Errorf("expected iin=123456789011, got %q", info.Subject.IIN)
	}
	if info.Subject.SurName != "ТЕСТОВ" {
		t.Errorf("expected surName=ТЕСТОВ, got %q", info.Subject.SurName)
	}
	if info.SignAlg != "ECGOST3410-2015-512" {
		t.Errorf("expected signAlg=ECGOST3410-2015-512, got %q", info.SignAlg)
	}
	if info.SerialNumber != "6c425659bd2fc6dc587b871aede1857727cf8451" {
		t.Errorf("unexpected serial number %q", info.SerialNumber)
	}
	if len(info.Revocations) != 1 || info.Revocations[0].By != "OCSP" || info.Revocations[0].Revoked {
		t.Errorf("unexpected revocations: %+v", info.Revocations)
	}
}

func TestBuildIndividualRevokedCRL(t *testing.T) {
	cli := newTestClient(t)
	cert := exportCert(t, cli, "../testdata/certs/individual/revoked/individual_revoked.p12")

	crlData, err := os.ReadFile("../testdata/certs/nca_gost2022_test.crl")
	if err != nil {
		t.Fatalf("read crl fixture: %s", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(crlData) //nolint:errcheck
	}))
	defer srv.Close()

	crl := crlservice.New(t.TempDir(), true, []string{srv.URL}, time.Hour, nil, 0)
	if err := crl.Bootstrap(context.Background()); err != nil {
		t.Fatalf("crl bootstrap: %s", err)
	}

	info, err := Build(cli, crl, cert, false, true)
	if err != nil {
		t.Fatalf("Build: %s", err)
	}

	if info.Valid {
		t.Error("expected valid=false for revoked cert")
	}
	if len(info.Revocations) != 1 || info.Revocations[0].By != "CRL" || !info.Revocations[0].Revoked {
		t.Errorf("expected a revoked CRL entry, got: %+v", info.Revocations)
	}
}

func TestBuildSelfSignedNeverValid(t *testing.T) {
	cli := newTestClient(t)

	data, err := os.ReadFile("../testdata/certs/root_test_gost_2022.cer")
	if err != nil {
		t.Fatalf("read root cert: %s", err)
	}

	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))

	info, err := Build(cli, nil, pemCert, true, true)
	if err != nil {
		t.Fatalf("Build: %s", err)
	}

	if info.Valid {
		t.Error("expected self-signed certificate to never be valid")
	}
	if len(info.Revocations) != 0 {
		t.Errorf("expected no revocation checks performed on self-signed cert, got: %+v", info.Revocations)
	}
}
