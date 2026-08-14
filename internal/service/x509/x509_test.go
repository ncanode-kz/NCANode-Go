package x509

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func signerReq(t *testing.T, p12RelPath string) dto.SignerRequest {
	t.Helper()

	key := testutil.ReadFixture(t, p12RelPath)

	return dto.SignerRequest{
		Key:      base64.StdEncoding.EncodeToString(key),
		Password: testutil.TestCertPassword,
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.SbaSignRequest{
		Data:   "x509 sign/verify test",
		Signer: signerReq(t, "individual/valid/individual_valid.p12"),
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}
	if signResp.Certificate == "" || signResp.Signature == "" {
		t.Fatalf("expected non-empty certificate/signature, got %+v", signResp)
	}

	verifyResp, err := verify(a, dto.SbaVerifyRequest{
		Certificate: signResp.Certificate,
		Signature:   signResp.Signature,
		Data:        "x509 sign/verify test",
	})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 1 || verifyResp.Signers[0] == nil {
		t.Fatalf("expected 1 non-nil signer, got %+v", verifyResp.Signers)
	}
	if verifyResp.Signers[0].Subject.IIN != "123456789011" {
		t.Errorf("unexpected iin: %q", verifyResp.Signers[0].Subject.IIN)
	}
}

func TestVerifyWrongDataFails(t *testing.T) {
	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.SbaSignRequest{
		Data:   "original data",
		Signer: signerReq(t, "individual/valid/individual_valid.p12"),
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.SbaVerifyRequest{
		Certificate: signResp.Certificate,
		Signature:   signResp.Signature,
		Data:        "tampered data",
	})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if verifyResp.Valid {
		t.Fatal("expected valid=false for tampered data")
	}
}

func TestInfoBatch(t *testing.T) {
	a := testutil.NewApp(t)

	certDER := certDERFromP12(t, a, "individual/valid/individual_valid.p12")
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	resp, err := info(a, dto.X509InfoRequest{Certs: []string{certB64, "not-valid-base64!!"}})
	if err != nil {
		t.Fatalf("info: %s", err)
	}

	if resp.Valid {
		t.Fatal("expected valid=false due to bad second entry")
	}
	if len(resp.Signers) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Signers))
	}
	if resp.Signers[0] == nil || !resp.Signers[0].Valid {
		t.Errorf("expected first signer to be valid, got %+v", resp.Signers[0])
	}
	if resp.Signers[1] != nil {
		t.Errorf("expected second signer to be nil, got %+v", resp.Signers[1])
	}
}

func TestInfoEmptyCertsIsInvalid(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := info(a, dto.X509InfoRequest{})
	if err != nil {
		t.Fatalf("info: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for empty certs list")
	}
}

func TestRegisterRoutesSmoke(t *testing.T) {
	a := testutil.NewApp(t)

	s := httpapi.New(false)
	RegisterRoutes(s, a)

	if s.Handler() == nil {
		t.Fatal("expected handler to be set")
	}
}

func certDERFromP12(t *testing.T, a *app.App, p12RelPath string) []byte {
	t.Helper()

	signResp, err := sign(a, dto.SbaSignRequest{
		Data:   "probe",
		Signer: signerReq(t, p12RelPath),
	})
	if err != nil {
		t.Fatalf("sign (for cert extraction): %s", err)
	}

	der, err := base64.StdEncoding.DecodeString(signResp.Certificate)
	if err != nil {
		t.Fatalf("decode certificate: %s", err)
	}

	return der
}
