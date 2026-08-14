//go:build oracle

package wsse

import (
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOracleWsseSignVerifyInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)
	key, password := signerReqFields(t, "individual/valid/individual_valid.p12")

	signResp, err := sign(a, dto.WsseSignRequest{
		XML:      "<test>ncanode-go wsse oracle interop</test>",
		Key:      key,
		Password: password,
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	javaResp, err := oc.Post("/wsse/verify", oracle.M{"xml": signResp.XML, "revocationCheck": []string{}})
	if err != nil {
		t.Fatalf("oracle /wsse/verify: %s", err)
	}
	t.Logf("java verify of go-signed wsse envelope: %+v", javaResp)
	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}

	// обратное направление
	fullEnvelope := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><test>java oracle wsse interop reverse</test></soap:Body>` +
		`</soap:Envelope>`

	javaSign, err := oc.Post("/wsse/sign", oracle.M{"xml": fullEnvelope, "key": key, "password": password})
	if err != nil {
		t.Fatalf("oracle /wsse/sign: %s", err)
	}
	javaXML, _ := javaSign["xml"].(string)
	if javaXML == "" {
		t.Fatalf("expected non-empty xml from oracle, got: %+v", javaSign)
	}

	verifyResp, err := verify(a, javaXML, false, false)
	if err != nil {
		t.Fatalf("verify(java-signed wsse envelope): %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true for java-signed envelope, got: %+v", verifyResp)
	}
}
