//go:build oracle

package jwt

import (
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOracleJwtEncodeDecodeInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)
	certB64 := certDERBase64(t, a, "individual/valid/individual_valid.p12")

	var req dto.JwtEncodeRequest
	req.Key = keyB64(t, "individual/valid/individual_valid.p12")
	req.Password = testutil.TestCertPassword
	req.JWT.Header.Alg = "GG2015"
	req.JWT.Header.Typ = "JWT"
	req.JWT.Payload = map[string]any{"sub": "ncanode-go oracle jwt interop"}

	encResp, err := encode(a, req)
	if err != nil {
		t.Fatalf("encode: %s", err)
	}

	javaResp, err := oc.Post("/jwt/decode", oracle.M{"jwt": encResp.JWT, "key": certB64})
	if err != nil {
		t.Fatalf("oracle /jwt/decode: %s", err)
	}
	t.Logf("java decode of go-issued jwt: %+v", javaResp)

	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}

	// обратное направление: java подписывает, мы проверяем
	key := keyB64(t, "individual/valid/individual_valid.p12")
	javaEnc, err := oc.Post("/jwt/encode", oracle.M{
		"jwt": oracle.M{
			"header":  oracle.M{"alg": "GG2015", "typ": "JWT"},
			"payload": oracle.M{"sub": "java oracle jwt interop reverse"},
		},
		"key":      key,
		"password": testutil.TestCertPassword,
	})
	if err != nil {
		t.Fatalf("oracle /jwt/encode: %s", err)
	}

	javaJWT, _ := javaEnc["jwt"].(string)
	if javaJWT == "" {
		t.Fatalf("expected non-empty jwt from oracle, got: %+v", javaEnc)
	}

	decResp, err := decode(a, dto.JwtDecodeRequest{JWT: javaJWT, Key: certB64})
	if err != nil {
		t.Fatalf("decode(java-issued jwt): %s", err)
	}
	if !decResp.Valid {
		t.Fatalf("expected valid=true for java-issued jwt, got: %+v", decResp)
	}
}
