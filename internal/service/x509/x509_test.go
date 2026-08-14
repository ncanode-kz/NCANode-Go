package x509

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestInfoBuildFailureOnGarbageCert(t *testing.T) {
	a := testutil.NewApp(t)

	garbage := base64.StdEncoding.EncodeToString([]byte("this is not a certificate"))

	resp, err := info(a, dto.X509InfoRequest{Certs: []string{garbage}})
	if err != nil {
		t.Fatalf("info: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for a garbage certificate")
	}
	if len(resp.Signers) != 1 || resp.Signers[0] != nil {
		t.Fatalf("expected 1 nil signer, got %+v", resp.Signers)
	}
}

func TestInfoRevokedCertIsInvalid(t *testing.T) {
	a := testutil.NewApp(t)

	certDER := certDERFromP12(t, a, "individual/revoked/individual_revoked.p12")
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	resp, err := info(a, dto.X509InfoRequest{
		Certs:         []string{certB64},
		VerifyRequest: dto.VerifyRequest{RevocationCheck: []dto.RevocationCheck{dto.RevocationCheckCRL}},
	})
	if err != nil {
		t.Fatalf("info: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for a revoked certificate")
	}
	if len(resp.Signers) != 1 || resp.Signers[0] == nil || resp.Signers[0].Valid {
		t.Fatalf("expected 1 non-nil invalid signer, got %+v", resp.Signers)
	}
}

func TestSignEmptyKey(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := sign(a, dto.SbaSignRequest{Data: "no key"}); err == nil {
		t.Fatal("expected error for empty signer key")
	}
}

func TestSignLoadSignerFailure(t *testing.T) {
	a := testutil.NewApp(t)

	req := signerReq(t, "individual/valid/individual_valid.p12")
	req.Password = "wrong-password"

	if _, err := sign(a, dto.SbaSignRequest{Data: "bad password", Signer: req}); err == nil {
		t.Fatal("expected error for wrong key password")
	}
}

func TestVerifyCertificateInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := verify(a, dto.SbaVerifyRequest{Certificate: "not-base64!!", Signature: "AA==", Data: "x"})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for invalid base64 certificate")
	}
	if len(resp.Signers) != 1 || resp.Signers[0] != nil {
		t.Fatalf("expected 1 nil signer, got %+v", resp.Signers)
	}
}

func TestVerifySignatureInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	certDER := certDERFromP12(t, a, "individual/valid/individual_valid.p12")

	_, err := verify(a, dto.SbaVerifyRequest{
		Certificate: base64.StdEncoding.EncodeToString(certDER),
		Signature:   "not-base64!!",
		Data:        "x",
	})
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestVerifyBuildFailureOnGarbageCert(t *testing.T) {
	a := testutil.NewApp(t)

	garbage := base64.StdEncoding.EncodeToString([]byte("this is not a certificate"))

	_, err := verify(a, dto.SbaVerifyRequest{Certificate: garbage, Signature: "AA==", Data: "x"})
	if err == nil {
		t.Fatal("expected error building certificate info from a garbage certificate")
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

func TestRegisterRoutesHTTP(t *testing.T) {
	a := testutil.NewApp(t)

	s := httpapi.New(false)
	RegisterRoutes(s, a)

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	signer := signerReq(t, "individual/valid/individual_valid.p12")

	buf, _ := json.Marshal(map[string]any{
		"data":   "http route test",
		"signer": map[string]string{"key": signer.Key, "password": signer.Password},
	})
	resp, err := http.Post(srv.URL+"/x509/sign", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post /x509/sign: %s", err)
	}
	defer resp.Body.Close()

	var signed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&signed); err != nil {
		t.Fatalf("decode: %s", err)
	}
	cert, _ := signed["certificate"].(string)
	sig, _ := signed["signature"].(string)
	if cert == "" || sig == "" {
		t.Fatalf("expected non-empty certificate/signature from /x509/sign, got: %+v", signed)
	}

	buf2, _ := json.Marshal(map[string]any{"certificate": cert, "signature": sig, "data": "http route test"})
	resp2, err := http.Post(srv.URL+"/x509/verify", "application/json", bytes.NewReader(buf2))
	if err != nil {
		t.Fatalf("post /x509/verify: %s", err)
	}
	defer resp2.Body.Close()

	var verified map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&verified); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if valid, _ := verified["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from /x509/verify, got: %+v", verified)
	}

	buf3, _ := json.Marshal(map[string]any{"certs": []string{cert}})
	resp3, err := http.Post(srv.URL+"/x509/info", "application/json", bytes.NewReader(buf3))
	if err != nil {
		t.Fatalf("post /x509/info: %s", err)
	}
	defer resp3.Body.Close()

	var infoResp map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&infoResp); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if valid, _ := infoResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from /x509/info, got: %+v", infoResp)
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
