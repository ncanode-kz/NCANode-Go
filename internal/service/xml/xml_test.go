package xml

import (
	"encoding/base64"
	"testing"

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

	signResp, err := sign(a, dto.XmlSignRequest{
		XML:     "<root><data>xml handler test</data></root>",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}
	if signResp.XML == "" {
		t.Fatal("expected non-empty xml")
	}

	verifyResp, err := verify(a, signResp.XML, false, false)
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

func TestMultiSignerOrderAndCount(t *testing.T) {
	a := testutil.NewApp(t)

	// первый подписант - individual (IIN), второй - legal head (BIN)
	first, err := sign(a, dto.XmlSignRequest{
		XML:     "<root><data>multisign order test</data></root>",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	})
	if err != nil {
		t.Fatalf("first sign: %s", err)
	}

	second, err := sign(a, dto.XmlSignRequest{
		XML:     first.XML,
		Signers: []dto.SignerRequest{signerReq(t, "legal/valid/head.p12")},
	})
	if err != nil {
		t.Fatalf("second sign: %s", err)
	}

	verifyResp, err := verify(a, second.XML, false, false)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(verifyResp.Signers))
	}
	for i, s := range verifyResp.Signers {
		t.Logf("signer[%d]: IIN=%q BIN=%q", i, s.Subject.IIN, s.Subject.BIN)
	}
}

func TestClearSignatures(t *testing.T) {
	a := testutil.NewApp(t)

	signed, err := sign(a, dto.XmlSignRequest{
		XML:     "<root><data>clear sig test</data></root>",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	resigned, err := sign(a, dto.XmlSignRequest{
		XML:             signed.XML,
		ClearSignatures: true,
		Signers:         []dto.SignerRequest{signerReq(t, "legal/valid/head.p12")},
	})
	if err != nil {
		t.Fatalf("resign with clearSignatures: %s", err)
	}

	verifyResp, err := verify(a, resigned.XML, false, false)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if len(verifyResp.Signers) != 1 {
		t.Fatalf("expected 1 signer after clearSignatures, got %d", len(verifyResp.Signers))
	}
}

func TestVerifyNoSignatures(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := verify(a, "<root><data>no signature</data></root>", false, false)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for unsigned xml")
	}
	if len(resp.Signers) != 0 {
		t.Fatalf("expected 0 signers, got %d", len(resp.Signers))
	}
}

func TestSignNoSigners(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := sign(a, dto.XmlSignRequest{XML: "<root/>"}); err == nil {
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
