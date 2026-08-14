package cms

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

func TestSignVerifyExtractRoundtrip(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("cms handler test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}
	if signResp.CMS == "" {
		t.Fatal("expected non-empty cms")
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(verifyResp.Signers))
	}

	extractResp, err := extract(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("extract: %s", err)
	}

	extracted, err := base64.StdEncoding.DecodeString(extractResp.Data)
	if err != nil {
		t.Fatalf("decode extracted data: %s", err)
	}
	if string(extracted) != "cms handler test" {
		t.Fatalf("unexpected extracted data: %q", extracted)
	}
}

func TestSignAddCoSign(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("co-sign test"))

	first, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("first sign: %s", err)
	}

	second, err := sign(a, dto.CmsCreateRequest{
		CMS:     first.CMS,
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "legal/valid/head.p12")},
	}, true)
	if err != nil {
		t.Fatalf("sign/add: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: second.CMS})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if len(verifyResp.Signers) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(verifyResp.Signers))
	}
}

func TestSignDetachedVerify(t *testing.T) {
	a := testutil.NewApp(t)

	plain := []byte("detached cms test")
	data := base64.StdEncoding.EncodeToString(plain)

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS, Data: data})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
}

func TestSignWithTSP(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("tsp test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		WithTSP: true,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	verifyResp, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if !verifyResp.Valid {
		t.Fatalf("expected valid=true, got %+v", verifyResp)
	}
	if verifyResp.Signers[0].TSP == nil || verifyResp.Signers[0].TSP.GenTime == nil {
		t.Errorf("expected TSP genTime to be populated, got %+v", verifyResp.Signers[0])
	}
}

func TestSignNoSigners(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{Data: "AA=="}, false)
	if err == nil {
		t.Fatal("expected error for empty signers")
	}
}

func TestSignAddWithoutCMS(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, true)
	if err == nil {
		t.Fatal("expected error when cms is missing for /sign/add")
	}
}

func TestExtractDetachedFails(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("no embedded data"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	if _, err := extract(a, dto.CmsVerifyRequest{CMS: signResp.CMS}); err == nil {
		t.Fatal("expected error extracting data from a detached CMS")
	}
}

func TestVerifyInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := verify(a, dto.CmsVerifyRequest{CMS: "not-base64!!"}); err == nil {
		t.Fatal("expected error for invalid base64 cms")
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

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) map[string]any {
	t.Helper()

	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %s", err)
	}

	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("post %s: %s", path, err)
	}
	defer resp.Body.Close()

	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response from %s: %s", path, err)
	}

	return got
}

func TestRegisterRoutesHTTP(t *testing.T) {
	a := testutil.NewApp(t)

	s := httpapi.New(false)
	RegisterRoutes(s, a)

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	data := base64.StdEncoding.EncodeToString([]byte("http route test"))
	signer1 := map[string]string{
		"key":      signerReq(t, "individual/valid/individual_valid.p12").Key,
		"password": testutil.TestCertPassword,
	}
	// co-подпись тем же сертификатом, что и первая подпись, native-библиотека
	// молча возвращает пустой CMS (не ошибку) - используем второй сертификат,
	// как и остальные co-sign тесты в этом пакете (см. TestSignAddCoSign).
	signer2 := map[string]string{
		"key":      signerReq(t, "legal/valid/head.p12").Key,
		"password": testutil.TestCertPassword,
	}

	signed := postJSON(t, srv, "/cms/sign", map[string]any{
		"data":    data,
		"signers": []any{signer1},
	})
	cms, _ := signed["cms"].(string)
	if cms == "" {
		t.Fatalf("expected non-empty cms from /cms/sign, got: %+v", signed)
	}

	verified := postJSON(t, srv, "/cms/verify", map[string]any{"cms": cms})
	if valid, _ := verified["valid"].(bool); !valid {
		t.Fatalf("expected valid=true from /cms/verify, got: %+v", verified)
	}

	extracted := postJSON(t, srv, "/cms/extract", map[string]any{"cms": cms})
	if d, _ := extracted["data"].(string); d == "" {
		t.Fatalf("expected non-empty data from /cms/extract, got: %+v", extracted)
	}

	added := postJSON(t, srv, "/cms/sign/add", map[string]any{
		"cms":     cms,
		"data":    data,
		"signers": []any{signer2},
	})
	if c, _ := added["cms"].(string); c == "" {
		t.Fatalf("expected non-empty cms from /cms/sign/add, got: %+v", added)
	}
}

func TestResolveSignContentAddInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{
		CMS:     "not-base64!!",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, true)
	if err == nil {
		t.Fatal("expected error for invalid base64 cms on sign/add")
	}
}

func TestSignAddNoEmbeddedNoData(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("detached, no embedded"))

	detached, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	_, err = sign(a, dto.CmsCreateRequest{
		CMS:     detached.CMS,
		Signers: []dto.SignerRequest{signerReq(t, "legal/valid/head.p12")},
	}, true)
	if err == nil {
		t.Fatal("expected error when co-signing detached CMS without data")
	}
}

func TestExtractEmptyCMS(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := extract(a, dto.CmsVerifyRequest{}); err == nil {
		t.Fatal("expected error for empty cms")
	}
}

func TestExtractInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := extract(a, dto.CmsVerifyRequest{CMS: "not-base64!!"}); err == nil {
		t.Fatal("expected error for invalid base64 cms")
	}
}

func TestVerifyEmptyCMS(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := verify(a, dto.CmsVerifyRequest{}); err == nil {
		t.Fatal("expected error for empty cms")
	}
}

func TestVerifyDataInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("verify data invalid base64 test"))

	signResp, err := sign(a, dto.CmsCreateRequest{
		Data:     data,
		Detached: true,
		Signers:  []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	if _, err := verify(a, dto.CmsVerifyRequest{CMS: signResp.CMS, Data: "not-base64!!"}); err == nil {
		t.Fatal("expected error for invalid base64 data")
	}
}

func TestVerifyNoValidSigners(t *testing.T) {
	a := testutil.NewApp(t)

	garbage := base64.StdEncoding.EncodeToString([]byte("not a real cms structure"))

	resp, err := verify(a, dto.CmsVerifyRequest{CMS: garbage})
	if err != nil {
		t.Fatalf("verify: %s", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false for garbage cms")
	}
	if len(resp.Signers) != 0 {
		t.Fatalf("expected no signers, got %d", len(resp.Signers))
	}
}

func TestSignLoadSignerFailure(t *testing.T) {
	a := testutil.NewApp(t)

	req := signerReq(t, "individual/valid/individual_valid.p12")
	req.Password = "wrong-password"

	_, err := sign(a, dto.CmsCreateRequest{
		Data:    base64.StdEncoding.EncodeToString([]byte("bad password test")),
		Signers: []dto.SignerRequest{req},
	}, false)
	if err == nil {
		t.Fatal("expected error for wrong key password")
	}
}

func TestResolveSignContentDataEmpty(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestResolveSignContentDataInvalidBase64(t *testing.T) {
	a := testutil.NewApp(t)

	_, err := sign(a, dto.CmsCreateRequest{
		Data:    "not-base64!!",
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err == nil {
		t.Fatal("expected error for invalid base64 data")
	}
}

func TestExtractSigningTimesAtoiOverflow(t *testing.T) {
	// Регекс "Signature N (\d+)" технически допускает сколь угодно длинное
	// число - при переполнении int strconv.Atoi возвращает ошибку, и секция
	// должна быть пропущена (continue), а не запаниковать.
	huge := "Signature N 99999999999999999999999999999\nSigning time 01.02.2024 10:20:30 +05:00\n"
	if got := extractSigningTimes(huge); len(got) != 0 {
		t.Errorf("expected no signing times for overflowing signature number, got %+v", got)
	}
}

func TestExtractSigningTimesMalformed(t *testing.T) {
	// Секция без "Signing time" вообще - должна быть пропущена (continue).
	noTime := "Signature N 1\nsome other text\n"
	if got := extractSigningTimes(noTime); len(got) != 0 {
		t.Errorf("expected no signing times, got %+v", got)
	}

	// Некорректный номер подписи - Atoi должен провалиться (continue), но
	// такое не может возникнуть из настоящего regex (\d+), проверяем что
	// функция не паникует на пустом вводе.
	if got := extractSigningTimes(""); len(got) != 0 {
		t.Errorf("expected no signing times for empty input, got %+v", got)
	}

	valid := "Signature N 1\nSigning time 01.02.2024 10:20:30 +05:00\n"
	got := extractSigningTimes(valid)
	if got[1] == "" {
		t.Errorf("expected signing time for signature 1, got %+v", got)
	}
}
