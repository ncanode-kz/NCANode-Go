package kalkanutil

import "testing"

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
