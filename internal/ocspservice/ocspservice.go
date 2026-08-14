// Package ocspservice - тонкая обёртка над OCSP-конфигурацией (URL из
// NCANODE_OCSP_URL). Сама проверка выполняется нативной библиотекой через
// gokalkan.Client.ValidateCertOCSP - этому пакету не нужно ничего кэшировать
// (в отличие от CA/CRL), только предоставлять сконфигурированный URL.
package ocspservice

type Service struct {
	url string
}

func New(url string) *Service { return &Service{url: url} }

func (s *Service) URL() string { return s.url }
