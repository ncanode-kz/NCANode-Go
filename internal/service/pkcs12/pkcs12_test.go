package pkcs12

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestInfoValidAndRevoked(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := info(a, dto.Pkcs12InfoRequest{
		Keys: []dto.SignerRequest{
			signerReq(t, "individual/valid/individual_valid.p12"),
			signerReq(t, "individual/revoked/individual_revoked.p12"),
		},
		VerifyRequest: dto.VerifyRequest{RevocationCheck: []dto.RevocationCheck{dto.RevocationCheckCRL}},
	})
	if err != nil {
		t.Fatalf("info: %s", err)
	}

	if resp.Valid {
		t.Fatal("expected overall valid=false (second key is revoked)")
	}
	if len(resp.Signers) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(resp.Signers))
	}
	if resp.Signers[0] == nil || !resp.Signers[0].Valid {
		t.Errorf("expected first signer valid, got %+v", resp.Signers[0])
	}
	if resp.Signers[1] == nil || resp.Signers[1].Valid {
		t.Errorf("expected second signer invalid (revoked), got %+v", resp.Signers[1])
	}
}

func TestInfoEmptyKeys(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := info(a, dto.Pkcs12InfoRequest{}); err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestInfoBadPassword(t *testing.T) {
	a := testutil.NewApp(t)

	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	_, err := info(a, dto.Pkcs12InfoRequest{
		Keys: []dto.SignerRequest{{Key: base64.StdEncoding.EncodeToString(key), Password: "wrong"}},
	})
	if err == nil {
		t.Fatal("expected error for bad password")
	}
}

func TestAliases(t *testing.T) {
	a := testutil.NewApp(t)

	resp, err := aliases(a, dto.Pkcs12InfoRequest{
		Keys: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	})
	if err != nil {
		t.Fatalf("aliases: %s", err)
	}
	if len(resp.Aliases) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Aliases))
	}
}

func TestAliasesEmptyKeys(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := aliases(a, dto.Pkcs12InfoRequest{}); err == nil {
		t.Fatal("expected error for empty keys")
	}
}

func TestAliasesBadPassword(t *testing.T) {
	a := testutil.NewApp(t)

	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	_, err := aliases(a, dto.Pkcs12InfoRequest{
		Keys: []dto.SignerRequest{{Key: base64.StdEncoding.EncodeToString(key), Password: "wrong"}},
	})
	if err == nil {
		t.Fatal("expected error for bad password")
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
		"keys": []any{map[string]string{"key": signer.Key, "password": signer.Password}},
	})

	resp, err := http.Post(srv.URL+"/pkcs12/info", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post /pkcs12/info: %s", err)
	}
	defer resp.Body.Close()

	var infoResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&infoResp); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if valid, _ := infoResp["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from /pkcs12/info, got: %+v", infoResp)
	}

	resp2, err := http.Post(srv.URL+"/pkcs12/aliases", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post /pkcs12/aliases: %s", err)
	}
	defer resp2.Body.Close()

	var aliasesResp map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&aliasesResp); err != nil {
		t.Fatalf("decode: %s", err)
	}
	if _, ok := aliasesResp["aliases"]; !ok {
		t.Fatalf("expected aliases field, got: %+v", aliasesResp)
	}
}
