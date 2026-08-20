package certservice

import "testing"

func TestZZDebugOCSPRaw(t *testing.T) {
	cli := newTestClient(t)
	cert := exportCert(t, cli, "../testdata/certs/individual/valid/individual_valid.p12")

	raw, err := cli.ValidateCertOCSP(cert)
	t.Errorf("DEBUG raw=%q err=%v", raw, err)

	sig, err := cli.Sign([]byte("debug sign test"), true, false)
	t.Errorf("DEBUG sign len=%d err=%v", len(sig), err)
}
