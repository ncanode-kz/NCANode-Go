//go:build oracle

package pdf

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOraclePdfSignVerifyInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	signResp, err := sign(a, dto.PdfSignRequest{
		PDF:     samplePDFBase64(t),
		WithTSP: true,
		Signers: []dto.PdfSigner{
			{Reason: "oracle interop", Location: "Almaty", Signer: signerReq(t, "individual/valid/individual_valid.p12")},
		},
	})
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	javaResp, err := oc.Post("/pdf/verify", oracle.M{"pdf": signResp.PDF, "revocationCheck": []string{}})
	if err != nil {
		t.Fatalf("oracle /pdf/verify: %s", err)
	}
	t.Logf("java verify of go-signed pdf: %+v", javaResp)
	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}

	// обратное направление: java подписывает, мы проверяем
	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	javaSign, err := oc.Post("/pdf/sign", oracle.M{
		"pdf": samplePDFBase64(t),
		"signers": []oracle.M{
			{
				"reason": "java oracle interop reverse",
				"signer": oracle.M{"key": base64.StdEncoding.EncodeToString(key), "password": testutil.TestCertPassword},
			},
		},
		"withTsp": true,
	})
	if err != nil {
		t.Fatalf("oracle /pdf/sign: %s", err)
	}
	javaPDF, _ := javaSign["pdf"].(string)
	if javaPDF == "" {
		t.Fatalf("expected non-empty pdf from oracle, got: %+v", javaSign)
	}

	verifyResp, err := verify(a, dto.PdfVerifyRequest{PDF: javaPDF})
	if err != nil {
		t.Fatalf("verify(java-signed pdf): %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true for java-signed pdf, got: %+v", verifyResp)
	}
}
