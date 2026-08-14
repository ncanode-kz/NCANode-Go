package dto

import "testing"

func TestOK(t *testing.T) {
	s := OK()
	if s.Status != 200 || s.Message != "OK" {
		t.Errorf("unexpected OK(): %+v", s)
	}
}

func TestVerifyRequestHasChecks(t *testing.T) {
	r := VerifyRequest{RevocationCheck: []RevocationCheck{RevocationCheckOCSP}}

	if !r.HasOCSP() {
		t.Error("expected HasOCSP=true")
	}
	if r.HasCRL() {
		t.Error("expected HasCRL=false")
	}

	empty := VerifyRequest{}
	if empty.HasOCSP() || empty.HasCRL() {
		t.Error("expected no checks on empty request")
	}
}
