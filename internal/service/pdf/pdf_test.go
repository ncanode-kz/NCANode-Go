package pdf

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func samplePDFBase64(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("../../testdata/pdf/sample.pdf")
	if err != nil {
		t.Fatalf("read sample pdf: %s", err)
	}

	return base64.StdEncoding.EncodeToString(data)
}

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

	signResp, err := sign(a, dto.PdfSignRequest{
		PDF: samplePDFBase64(t),
		Signers: []dto.PdfSigner{
			{Reason: "pdf handler test", Location: "Almaty", Signer: signerReq(t, "individual/valid/individual_valid.p12")},
		},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}
	if signResp.PDF == "" {
		t.Fatal("expected non-empty pdf")
	}

	verifyResp, err := verify(a, dto.PdfVerifyRequest{PDF: signResp.PDF})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(verifyResp.Signers))
	}

	s := verifyResp.Signers[0]
	if s.Reason != "pdf handler test" || s.Location != "Almaty" {
		t.Errorf("unexpected reason/location: %+v", s)
	}
	if s.SignatureAlgorithm != "ETSI.CAdES.detached" {
		t.Errorf("unexpected signatureAlgorithm: %q", s.SignatureAlgorithm)
	}
	if s.Certificate == nil || s.Certificate.Subject.IIN != "123456789011" {
		t.Errorf("unexpected certificate: %+v", s.Certificate)
	}
	if s.SignDate == nil {
		t.Error("expected non-nil signDate")
	}
}

func TestSignWithTSP(t *testing.T) {
	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.PdfSignRequest{
		PDF:     samplePDFBase64(t),
		WithTSP: true,
		Signers: []dto.PdfSigner{
			{Reason: "tsp test", Signer: signerReq(t, "individual/valid/individual_valid.p12")},
		},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.PdfVerifyRequest{PDF: signResp.PDF})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
}

func TestMultiSigner(t *testing.T) {
	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.PdfSignRequest{
		PDF: samplePDFBase64(t),
		Signers: []dto.PdfSigner{
			{Reason: "first", Signer: signerReq(t, "individual/valid/individual_valid.p12")},
			{Reason: "second", Signer: signerReq(t, "legal/valid/head.p12")},
		},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.PdfVerifyRequest{PDF: signResp.PDF})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(verifyResp.Signers))
	}
}

func TestVerifyNoSignatures(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := verify(a, dto.PdfVerifyRequest{PDF: samplePDFBase64(t)})
	if err == nil {
		t.Fatal("expected error for pdf with no signatures")
	}
}

func TestSignNoSigners(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := sign(a, dto.PdfSignRequest{PDF: samplePDFBase64(t)}); err == nil {
		t.Fatal("expected error for empty signers")
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
