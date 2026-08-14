//go:build oracle

package cms

import (
	"encoding/base64"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

// TestOracleCmsSignVerifyInterop проверяет, что CMS, подписанный
// NCANode-Go (/cms/sign), успешно проходит верификацию в эталонном Java
// NCANode - и наоборот.
func TestOracleCmsSignVerifyInterop(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("ncanode-go oracle interop test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		WithTSP: true,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	javaResp, err := oc.Post("/cms/verify", oracle.M{
		"cms":             signResp.CMS,
		"revocationCheck": []string{},
	})
	if err != nil {
		t.Fatalf("oracle /cms/verify: %s", err)
	}
	t.Logf("java verify of go-signed cms: %+v", javaResp)

	if valid, _ := javaResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from java oracle, got: %+v", javaResp)
	}

	// обратное направление: java подписывает, мы проверяем
	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	javaSign, err := oc.Post("/cms/sign", oracle.M{
		"data": data,
		"signers": []oracle.M{
			{"key": base64.StdEncoding.EncodeToString(key), "password": testutil.TestCertPassword},
		},
		"withTsp": true,
	})
	if err != nil {
		t.Fatalf("oracle /cms/sign: %s", err)
	}

	javaCMS, _ := javaSign["cms"].(string)
	if javaCMS == "" {
		t.Fatalf("expected non-empty cms from oracle, got: %+v", javaSign)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: javaCMS})
	if err != nil {
		t.Fatalf("verify(java-signed cms): %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true for java-signed cms, got: %+v", verifyResp)
	}
}
