package jwt

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

func TestEncodeLoadSignerFailure(t *testing.T) {
	a := testutil.NewApp(t)

	var req dto.JwtEncodeRequest
	req.Key = keyB64(t, "individual/valid/individual_valid.p12")
	req.Password = "wrong-password"
	req.JWT.Header.Alg = "GG2015"

	if _, err := encode(a, req); err == nil {
		t.Fatal("expected error for wrong key password")
	}
}

func TestDecodeKeyInvalidBase64(t *testing.T) {
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

	if _, err := decode(a, dto.JwtDecodeRequest{JWT: encResp.JWT, Key: "not-base64!!"}); err == nil {
		t.Fatal("expected error for invalid base64 key")
	}
}

func TestDecodeJWTStructureErrors(t *testing.T) {
	if _, _, err := decodeJWTStructure("only.two"); err == nil {
		t.Error("expected error for a token without 3 parts")
	}
	if _, _, err := decodeJWTStructure("not-base64!!.eyJhIjoxfQ.sig"); err == nil {
		t.Error("expected error for invalid base64 header")
	}
	if _, _, err := decodeJWTStructure("bm90LWpzb24.eyJhIjoxfQ.sig"); err == nil {
		t.Error("expected error for non-JSON header")
	}
	if _, _, err := decodeJWTStructure("eyJhbGciOiJHRzIwMTUifQ.not-base64!!.sig"); err == nil {
		t.Error("expected error for invalid base64 payload")
	}
	if _, _, err := decodeJWTStructure("eyJhbGciOiJHRzIwMTUifQ.bm90LWpzb24.sig"); err == nil {
		t.Error("expected error for non-JSON payload")
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

	certB64 := certDERBase64(t, a, "individual/valid/individual_valid.p12")

	buf, _ := json.Marshal(map[string]any{
		"key":      keyB64(t, "individual/valid/individual_valid.p12"),
		"password": testutil.TestCertPassword,
		"jwt": map[string]any{
			"header":  map[string]string{"alg": "GG2015", "typ": "JWT"},
			"payload": map[string]any{"sub": "http route test"},
		},
	})
	resp, err := http.Post(srv.URL+"/jwt/encode", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post /jwt/encode: %s", err)
	}
	defer resp.Body.Close()

	var encoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&encoded); err != nil {
		t.Fatalf("decode: %s", err)
	}
	token, _ := encoded["jwt"].(string)
	if token == "" {
		t.Fatalf("expected non-empty jwt from /jwt/encode, got: %+v", encoded)
	}

	buf2, _ := json.Marshal(map[string]any{"jwt": token, "key": certB64})
	resp2, err := http.Post(srv.URL+"/jwt/decode", "application/json", bytes.NewReader(buf2))
	if err != nil {
		t.Fatalf("post /jwt/decode: %s", err)
	}
	defer resp2.Body.Close()

	var decoded map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if valid, _ := decoded["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from /jwt/decode, got: %+v", decoded)
	}
}
