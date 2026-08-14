//go:build oracle

package x509

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOracleX509SignVerifyInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.SbaSignRequest{
		Data:   "ncanode-go x509 oracle interop",
		Signer: signerReq(t, "individual/valid/individual_valid.p12"),
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	javaResp, err := oc.Post("/x509/verify", oracle.M{
		"certificate": signResp.Certificate,
		"signature":   signResp.Signature,
		"data":        "ncanode-go x509 oracle interop",
	})
	if err != nil {
		t.Fatalf("oracle /x509/verify: %s", err)
	}
	t.Logf("java verify of go-signed data: %+v", javaResp)

	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}
}

func TestOracleX509InfoMatchesFieldShape(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	certDER := certDERFromP12(t, a, "individual/valid/individual_valid.p12")
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	goResp, err := info(a, dto.X509InfoRequest{Certs: []string{certB64}})
	if err != nil {
		t.Fatalf("info: %s", err)
	}

	javaResp, err := oc.Post("/x509/info", oracle.M{
		"certs":           []string{certB64},
		"revocationCheck": []string{},
	})
	if err != nil {
		t.Fatalf("oracle /x509/info: %s", err)
	}
	t.Logf("go: %+v", goResp)
	t.Logf("java: %+v", javaResp)

	if valid, _ := javaResp["valid"].(bool); valid != goResp.Valid {
		t.Errorf("valid mismatch: go=%v java=%v", goResp.Valid, valid)
	}
}
