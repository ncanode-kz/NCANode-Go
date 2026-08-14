// Package config - конфигурация сервиса, 1:1 с application.yml оригинального
// NCANode (Java): те же имена переменных окружения NCANODE_*, те же дефолты.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port string

	Debug    bool
	CacheDir string

	CRL CRLConfig

	HTTPClient HTTPClientConfig

	OCSPURL string

	CA CAConfig

	TSP TSPConfig
}

type CRLConfig struct {
	Enabled   bool
	TTL       time.Duration
	URLs      []string
	DeltaURLs []string
	DeltaTTL  time.Duration
}

type HTTPClientConfig struct {
	ConnectionTTL time.Duration
	UserAgent     string
	ProxyURL      string
	ProxyUsername string
	ProxyPassword string
}

type CAConfig struct {
	URLs []string
	TTL  time.Duration
	CRL  CACRLConfig
}

type CACRLConfig struct {
	Enabled bool
	TTL     time.Duration
	URLs    []string
	Delta   CACRLDeltaConfig
}

type CACRLDeltaConfig struct {
	Enabled bool
	URLs    []string
	TTL     time.Duration
}

type TSPConfig struct {
	URL     string
	Retries int
}

// Load читает конфигурацию из переменных окружения, применяя те же дефолты,
// что и application.yml в Java NCANode.
func Load() Config {
	return Config{
		Port: env("NCANODE_PORT", "14579"),

		Debug:    envBool("NCANODE_DEBUG", false),
		CacheDir: env("NCANODE_CACHE_DIR", "./cache"),

		CRL: CRLConfig{
			Enabled: envBool("NCANODE_CRL_ENABLED", true),
			TTL:     envMinutes("NCANODE_CRL_TTL", 1440),
			URLs: envURLList("NCANODE_CRL_URL",
				"http://crl.pki.gov.kz/nca_rsa_2022.crl http://crl.pki.gov.kz/nca_gost_2022.crl"),
			DeltaURLs: envURLList("NCANODE_CRL_DELTA_URL",
				"http://crl.pki.gov.kz/nca_d_rsa_2022.crl http://crl.pki.gov.kz/nca_d_gost_2022.crl"),
			DeltaTTL: envMinutes("NCANODE_CRL_DELTA_TTL", 60),
		},

		HTTPClient: HTTPClientConfig{
			ConnectionTTL: envMinutes("NCANODE_HTTP_CLIENT_CONNECTION_TTL", 10),
			UserAgent:     env("NCANODE_HTTP_CLIENT_USER_AGENT", ""),
			ProxyURL:      env("NCANODE_PROXY_URL", ""),
			ProxyUsername: env("NCANODE_PROXY_USERNAME", ""),
			ProxyPassword: env("NCANODE_PROXY_PASSWORD", ""),
		},

		OCSPURL: env("NCANODE_OCSP_URL", "http://ocsp.pki.gov.kz/"),

		CA: CAConfig{
			URLs: envURLList("NCANODE_CA_URL",
				"http://pki.gov.kz/cert/nca_rsa.crt http://pki.gov.kz/cert/nca_gost.crt "+
					"http://pki.gov.kz/cert/root_gost_2022.cer http://root.gov.kz/cert/root_gost_2020.cer "+
					"http://root.gov.kz/cert/root_rsa_2020.cer http://pki.gov.kz/cert/nca_gost_2022.cer"),
			TTL: envMinutes("NCANODE_CA_TTL", 1440),
			CRL: CACRLConfig{
				Enabled: envBool("NCANODE_CA_CRL_ENABLED", true),
				TTL:     envMinutes("NCANODE_CA_CRL_TTL", 1440),
				URLs: envURLList("NCANODE_CA_CRL_URL",
					"http://crl.root.gov.kz/gost.crl http://crl.root.gov.kz/rsa.crl "+
						"http://crl.root.gov.kz/gost2020.crl http://crl.root.gov.kz/rsa2020.crl"),
				Delta: CACRLDeltaConfig{
					Enabled: envBool("NCANODE_CA_CRL_DELTA_ENABLED", false),
					URLs:    envURLList("NCANODE_CA_CRL_DELTA_URL", ""),
					TTL:     envMinutes("NCANODE_CA_CRL_DELTA_TTL", 0),
				},
			},
		},

		TSP: TSPConfig{
			URL:     env("NCANODE_TSP_URL", "http://tsp.pki.gov.kz/"),
			Retries: envInt("NCANODE_TSP_RETRIES", 3),
		},
	}
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envMinutes(key string, def int) time.Duration {
	return time.Duration(envInt(key, def)) * time.Minute
}

func envURLList(key, def string) []string {
	raw := env(key, def)
	fields := strings.Fields(raw)
	urls := make([]string, 0, len(fields))
	urls = append(urls, fields...)
	return urls
}
