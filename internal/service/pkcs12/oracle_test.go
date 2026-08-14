//go:build oracle

package pkcs12

import (
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/oracle"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestOraclePkcs12InfoMatches(t *testing.T) {
	oc := oracle.NewClient("")
	if !oc.Healthy() {
		t.Skip("oracle (NCANode Java) is not running on localhost:14579")
	}

	a := testutil.NewApp(t)
	signer := signerReq(t, "individual/valid/individual_valid.p12")

	goResp, err := info(a, dto.Pkcs12InfoRequest{Keys: []dto.SignerRequest{signer}})
	if err != nil {
		t.Fatalf("info: %s", err)
	}

	javaResp, err := oc.Post("/pkcs12/info", oracle.M{
		"keys":            []oracle.M{{"key": signer.Key, "password": signer.Password}},
		"revocationCheck": []string{},
	})
	if err != nil {
		t.Fatalf("oracle /pkcs12/info: %s", err)
	}
	t.Logf("go: %+v", goResp)
	t.Logf("java: %+v", javaResp)

	if valid, _ := javaResp["valid"].(bool); valid != goResp.Valid {
		t.Errorf("valid mismatch: go=%v java=%v", goResp.Valid, valid)
	}
}
