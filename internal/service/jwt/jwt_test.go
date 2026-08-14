package jwt

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func keyB64(t *testing.T, p12RelPath string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(testutil.ReadFixture(t, p12RelPath))
}

// certDERBase64 загружает ключ и возвращает его сертификат в base64(DER) -
// формате, который ожидает /jwt/decode.key.
func certDERBase64(t *testing.T, a *app.App, p12RelPath string) string {
	t.Helper()

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	certPEM, err := kalkanutil.LoadSigner(a.Shared, keyB64(t, p12RelPath), testutil.TestCertPassword)
	if err != nil {
		t.Fatalf("load signer: %s", err)
	}

	return base64.StdEncoding.EncodeToString(kalkanutil.DERFromPEMOrDER([]byte(certPEM)))
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	a := testutil.NewApp(t)

	certB64 := certDERBase64(t, a, "individual/valid/individual_valid.p12")

	var req dto.JwtEncodeRequest
	req.Key = keyB64(t, "individual/valid/individual_valid.p12")
	req.Password = testutil.TestCertPassword
	req.JWT.Header.Alg = "GG2015"
	req.JWT.Header.Typ = "JWT"
	req.JWT.Payload = map[string]any{"sub": "ncanode-go jwt test"}

	encResp, err := encode(a, req)
	if err != nil {
		t.Fatalf("encode: %s", err)
	}
	if encResp.JWT == "" {
		t.Fatal("expected non-empty jwt")
	}

	decResp, err := decode(a, dto.JwtDecodeRequest{JWT: encResp.JWT, Key: certB64})
	if err != nil {
		t.Fatalf("decode: %s", err)
	}
	if !decResp.Valid {
		t.Fatal("expected valid=true")
	}
	if decResp.JWT.Header["alg"] != "GG2015" {
		t.Errorf("unexpected header: %+v", decResp.JWT.Header)
	}
	if decResp.JWT.Payload["sub"] != "ncanode-go jwt test" {
		t.Errorf("unexpected payload: %+v", decResp.JWT.Payload)
	}
}

func TestDecodeWrongCertIsInvalidButStillParses(t *testing.T) {
	a := testutil.NewApp(t)

	var req dto.JwtEncodeRequest
	req.Key = keyB64(t, "individual/valid/individual_valid.p12")
	req.Password = testutil.TestCertPassword
	req.JWT.Header.Alg = "GG2015"
	req.JWT.Payload = map[string]any{"sub": "x"}

	encResp, err := encode(a, req)
	if err != nil {
		t.Fatalf("encode: %s", err)
	}

	wrongCert := certDERBase64(t, a, "legal/valid/head.p12")

	decResp, err := decode(a, dto.JwtDecodeRequest{JWT: encResp.JWT, Key: wrongCert})
	if err != nil {
		t.Fatalf("decode: %s", err)
	}
	if decResp.Valid {
		t.Error("expected valid=false when verifying against the wrong certificate")
	}
	// структура должна разбираться независимо от валидности подписи (как в Java)
	if decResp.JWT.Payload["sub"] != "x" {
		t.Errorf("expected payload to still be parsed, got %+v", decResp.JWT.Payload)
	}
}

func TestDecodeMalformedJWT(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := decode(a, dto.JwtDecodeRequest{JWT: "not-a-jwt", Key: "AA=="})
	if err == nil {
		t.Fatal("expected error for malformed jwt")
	}
}

func TestEncodeMissingKey(t *testing.T) {
	a := testutil.NewApp(t)

	var req dto.JwtEncodeRequest
	req.JWT.Header.Alg = "GG2015"

	if _, err := encode(a, req); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestEncodeMissingAlg(t *testing.T) {
	a := testutil.NewApp(t)

	var req dto.JwtEncodeRequest
	req.Key = keyB64(t, "individual/valid/individual_valid.p12")
	req.Password = testutil.TestCertPassword

	if _, err := encode(a, req); err == nil {
		t.Fatal("expected error for missing alg")
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
