package kalkanutil

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestPEMFromBase64Body(t *testing.T) {
	got := PEMFromBase64Body([]byte("YWJj"))
	want := "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
	if got != want {
		t.Fatalf("PEMFromBase64Body = %q, want %q", got, want)
	}
}

func TestLoadSigner(t *testing.T) {
	a := testutil.NewApp(t)

	key := testutil.ReadFixture(t, "individual/valid/individual_valid.p12")
	keyB64 := base64.StdEncoding.EncodeToString(key)

	certPEM, err := LoadSigner(a.Shared, keyB64, testutil.TestCertPassword)
	if err != nil {
		t.Fatalf("LoadSigner: %s", err)
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("expected PEM certificate, got: %s", certPEM)
	}
}

func TestLoadSignerBadBase64(t *testing.T) {
	a := testutil.NewApp(t)

	if _, err := LoadSigner(a.Shared, "not-base64!!", "pw"); err == nil {
		t.Fatal("expected error for invalid base64 key")
	}
}

func TestPEMFromDERRoundtrip(t *testing.T) {
	der := []byte{0x01, 0x02, 0x03, 0x04}

	pemStr := PEMFromDER(der)
	if pemStr == "" {
		t.Fatal("expected non-empty PEM")
	}

	got := DERFromPEMOrDER([]byte(pemStr))
	if string(got) != string(der) {
		t.Errorf("roundtrip mismatch: got %x, want %x", got, der)
	}
}

func TestDERFromPEMOrDERPassthrough(t *testing.T) {
	der := []byte{0xAA, 0xBB, 0xCC}

	got := DERFromPEMOrDER(der)
	if string(got) != string(der) {
		t.Errorf("expected passthrough for raw DER, got %x", got)
	}
}

func TestStripWhitespace(t *testing.T) {
	cases := map[string]string{
		"abc\n def\tghi\r\n": "abcdefghi",
		"nowhitespace":       "nowhitespace",
		"":                   "",
	}

	for in, want := range cases {
		if got := StripWhitespace(in); got != want {
			t.Errorf("StripWhitespace(%q) = %q, want %q", in, got, want)
		}
	}
}
