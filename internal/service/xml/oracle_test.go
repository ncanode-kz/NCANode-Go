//go:build oracle

package xml

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOracleXmlSignVerifyInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.XmlSignRequest{
		XML:     "<root><data>ncanode-go xml oracle interop</data></root>",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	javaResp, err := oc.Post("/xml/verify", oracle.M{"xml": signResp.XML, "revocationCheck": []string{}})
	if err != nil {
		t.Fatalf("oracle /xml/verify: %s", err)
	}
	t.Logf("java verify of go-signed xml: %+v", javaResp)
	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}

	// обратное направление: java подписывает, мы проверяем
	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	javaSign, err := oc.Post("/xml/sign", oracle.M{
		"xml": "<root><data>java oracle xml interop reverse</data></root>",
		"signers": []oracle.M{
			{"key": base64.StdEncoding.EncodeToString(key), "password": testutil.TestCertPassword},
		},
	})
	if err != nil {
		t.Fatalf("oracle /xml/sign: %s", err)
	}
	javaXML, _ := javaSign["xml"].(string)
	if javaXML == "" {
		t.Fatalf("expected non-empty xml from oracle, got: %+v", javaSign)
	}

	verifyResp, err := verify(a, javaXML, false, false)
	if err != nil {
		t.Fatalf("verify(java-signed xml): %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true for java-signed xml, got: %+v", verifyResp)
	}
}

// TestOracleXmlMultiSignerOrderMatches сверяет ПОРЯДОК подписантов в ответе
// /xml/verify между Go и Java на одном и том же multi-signer документе - у
// Java он "от последней подписи к первой" (см. XmlService.verify).
func TestOracleXmlMultiSignerOrderMatches(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	individualKey := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	legalKey := testutil.ReadFixture(t, "legal/valid/head.p12")

	javaSign, err := oc.Post("/xml/sign", oracle.M{
		"xml": "<root><data>multisign order</data></root>",
		"signers": []oracle.M{
			{"key": base64.StdEncoding.EncodeToString(individualKey), "password": testutil.TestCertPassword},
			{"key": base64.StdEncoding.EncodeToString(legalKey), "password": testutil.TestCertPassword},
		},
	})
	if err != nil {
		t.Fatalf("oracle /xml/sign: %s", err)
	}
	javaXML, _ := javaSign["xml"].(string)

	javaVerify, err := oc.Post("/xml/verify", oracle.M{"xml": javaXML, "revocationCheck": []string{}})
	if err != nil {
		t.Fatalf("oracle /xml/verify: %s", err)
	}
	javaSigners, _ := javaVerify["signers"].([]any)
	if len(javaSigners) != 2 {
		t.Fatalf("expected 2 signers from java, got %d: %+v", len(javaSigners), javaVerify)
	}
	javaFirst := javaSigners[0].(map[string]any)["subject"].(map[string]any)
	t.Logf("java signers[0].subject: %+v", javaFirst)

	goResp, err := verify(a, javaXML, false, false)
	if err != nil {
		t.Fatalf("go verify: %s", err)
	}
	if len(goResp.Signers) != 2 {
		t.Fatalf("expected 2 signers from go, got %d", len(goResp.Signers))
	}
	t.Logf("go signers[0].subject: IIN=%q BIN=%q", goResp.Signers[0].Subject.IIN, goResp.Signers[0].Subject.BIN)

	javaFirstBIN, _ := javaFirst["bin"].(string)
	if (javaFirstBIN != "") != (goResp.Signers[0].Subject.BIN != "") {
		t.Errorf("signer order mismatch: java first has bin=%q, go first has bin=%q",
			javaFirstBIN, goResp.Signers[0].Subject.BIN)
	}
}
