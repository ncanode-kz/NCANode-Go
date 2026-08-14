package wsse

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func signerReqFields(t *testing.T, p12RelPath string) (key, password string) {
	t.Helper()
	return base64.StdEncoding.EncodeToString(testutil.ReadFixture(t, p12RelPath)), testutil.TestCertPassword
}

func TestSignVerifyRoundtrip(t *testing.T) {
	a := testutil.NewApp(t)

	key, password := signerReqFields(t, "individual/valid/individual_valid.p12")

	signResp, err := sign(a, dto.WsseSignRequest{
		XML:      "<test>wsse handler test</test>",
		Key:      key,
		Password: password,
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

func TestSignWithTrimXML(t *testing.T) {
	a := testutil.NewApp(t)

	key, password := signerReqFields(t, "individual/valid/individual_valid.p12")

	signResp, err := sign(a, dto.WsseSignRequest{
		XML:      "<test>\n   trim test  \n</test>",
		Key:      key,
		Password: password,
		TrimXML:  true,
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, signResp.XML, false, false)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
}

func TestSignMissingKey(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := sign(a, dto.WsseSignRequest{XML: "<test/>"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestVerifyUnsigned(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := verify(a, "<test>not signed</test>", false, false)
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for unsigned xml")
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
