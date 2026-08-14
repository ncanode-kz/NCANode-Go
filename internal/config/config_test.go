package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

	if cfg.Port != "14579" {
		t.Errorf("expected default port 14579, got %q", cfg.Port)
	}
	if cfg.Debug {
		t.Error("expected debug=false by default")
	}
	if cfg.CacheDir != "./cache" {
		t.Errorf("unexpected default cache dir %q", cfg.CacheDir)
	}
	if !cfg.CRL.Enabled {
		t.Error("expected CRL enabled by default")
	}
	if cfg.CRL.TTL != 1440*time.Minute {
		t.Errorf("unexpected default CRL TTL %s", cfg.CRL.TTL)
	}
	if len(cfg.CRL.URLs) != 2 {
		t.Errorf("expected 2 default CRL URLs, got %d: %v", len(cfg.CRL.URLs), cfg.CRL.URLs)
	}
	if cfg.OCSPURL != "http://ocsp.pki.gov.kz/" {
		t.Errorf("unexpected default OCSP URL %q", cfg.OCSPURL)
	}
	if cfg.TSP.Retries != 3 {
		t.Errorf("expected default TSP retries 3, got %d", cfg.TSP.Retries)
	}
	if len(cfg.CA.URLs) != 6 {
		t.Errorf("expected 6 default CA URLs, got %d: %v", len(cfg.CA.URLs), cfg.CA.URLs)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("NCANODE_PORT", "9999")
	t.Setenv("NCANODE_DEBUG", "true")
	t.Setenv("NCANODE_CRL_ENABLED", "false")
	t.Setenv("NCANODE_CRL_TTL", "5")
	t.Setenv("NCANODE_OCSP_URL", "http://example.test/ocsp")
	t.Setenv("NCANODE_TSP_RETRIES", "7")
	t.Setenv("NCANODE_CA_URL", "http://a.test/1 http://a.test/2")

	cfg := Load()

	if cfg.Port != "9999" {
		t.Errorf("expected overridden port 9999, got %q", cfg.Port)
	}
	if !cfg.Debug {
		t.Error("expected debug=true")
	}
	if cfg.CRL.Enabled {
		t.Error("expected CRL disabled")
	}
	if cfg.CRL.TTL != 5*time.Minute {
		t.Errorf("unexpected CRL TTL %s", cfg.CRL.TTL)
	}
	if cfg.OCSPURL != "http://example.test/ocsp" {
		t.Errorf("unexpected OCSP URL %q", cfg.OCSPURL)
	}
	if cfg.TSP.Retries != 7 {
		t.Errorf("unexpected TSP retries %d", cfg.TSP.Retries)
	}
	if len(cfg.CA.URLs) != 2 {
		t.Errorf("expected 2 CA URLs, got %v", cfg.CA.URLs)
	}
}

func TestLoadInvalidValuesFallBackToDefaults(t *testing.T) {
	t.Setenv("NCANODE_DEBUG", "not-a-bool")
	t.Setenv("NCANODE_TSP_RETRIES", "not-a-number")

	cfg := Load()

	if cfg.Debug {
		t.Error("expected fallback to default (false) for invalid bool")
	}
	if cfg.TSP.Retries != 3 {
		t.Errorf("expected fallback to default (3) for invalid int, got %d", cfg.TSP.Retries)
	}
}
