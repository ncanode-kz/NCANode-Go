package cms

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

func TestSignVerifyExtractRoundtrip(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("cms handler test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}
	if signResp.CMS == "" {
		t.Fatal("expected non-empty cms")
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(verifyResp.Signers))
	}

	extractResp, err := extract(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("extract: %s", err)
	}

	extracted, err := base64.StdEncoding.DecodeString(extractResp.Data)
	if err != nil {
		t.Fatalf("decode extracted data: %s", err)
	}
	if string(extracted) != "cms handler test" {
		t.Fatalf("unexpected extracted data: %q", extracted)
	}
}

func TestSignAddCoSign(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("co-sign test"))

	first, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("first sign: %s", err)
	}

	second, err := sign(a, dto.CmsCreateRequest{
		CMS:     first.CMS,
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "legal/valid/head.p12")},
	}, true)
	if err != nil {
		t.Fatalf("sign/add: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: second.CMS})
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

func TestSignDetachedVerify(t *testing.T) {
	a := testutil.NewApp(t)

	plain := []byte("detached cms test")
	data := base64.StdEncoding.EncodeToString(plain)

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS, Data: data})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
}

func TestSignWithTSP(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("tsp test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		WithTSP: true,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if verifyResp.Signers[0].TSP == nil || verifyResp.Signers[0].TSP.GenTime == nil {
		t.Errorf("expected TSP genTime to be populated, got %+v", verifyResp.Signers[0])
	}
}

func TestSignNoSigners(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{Data: "AA=="}, false)
	if err == nil {
		t.Fatal("expected error for empty signers")
	}
}

func TestSignAddWithoutCMS(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, true)
	if err == nil {
		t.Fatal("expected error when cms is missing for /sign/add")
	}
}

func TestExtractDetachedFails(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("no embedded data"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	if _, err := extract(a, dto.CmsVerifyRequest{CMS: signResp.CMS}); err == nil {
		t.Fatal("expected error extracting data from a detached CMS")
	}
}

func TestVerifyInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := verify(a, dto.CmsVerifyRequest{CMS: "not-base64!!"}); err == nil {
		t.Fatal("expected error for invalid base64 cms")
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
