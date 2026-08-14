// Package caservice - аналог kz.ncanode.service.CaService: загружает и
// периодически обновляет корневые/промежуточные сертификаты УЦ, сконфигурированные
// через NCANODE_CA_URL. При неудаче на старте вызывающий код должен упасть
// (см. Java: System.exit(32)) - без валидных CA-сертификатов сервис не может
// строить доверенные цепочки.
package caservice

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ncanode-kz/gokalkan"
	"github.com/ncanode-kz/gokalkan/ckalkan"
)

type Service struct {
	urls []string
	ttl  time.Duration

	httpClient *http.Client

	mu    sync.RWMutex
	certs []gokalkan.OptionsCert
}

func New(urls []string, ttl time.Duration) *Service {
	return &Service{
		urls:       urls,
		ttl:        ttl,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Bootstrap загружает все сконфигурированные сертификаты. Возвращает ошибку,
// если хотя бы один URL не удалось загрузить или распарсить - вызывающий код
// должен считать это фатальным стартовым сбоем.
func (s *Service) Bootstrap(ctx context.Context) error {
	certs, err := s.fetchAll(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.certs = certs
	s.mu.Unlock()

	return nil
}

// StartBackgroundRefresh запускает фоновое обновление раз в TTL. Ошибки
// обновления логируются, но не считаются фатальными (используется
// последний успешно загруженный набор сертификатов).
func (s *Service) StartBackgroundRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.ttl)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				certs, err := s.fetchAll(ctx)
				if err != nil {
					slog.Error("ca certificate refresh failed, keeping previous set", "error", err)
					continue
				}

				s.mu.Lock()
				s.certs = certs
				s.mu.Unlock()
			}
		}
	}()
}

// Certs возвращает текущий загруженный набор CA/промежуточных сертификатов
// (для gokalkan.WithCerts).
func (s *Service) Certs() []gokalkan.OptionsCert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]gokalkan.OptionsCert, len(s.certs))
	copy(out, s.certs)

	return out
}

func (s *Service) fetchAll(ctx context.Context) ([]gokalkan.OptionsCert, error) {
	certs := make([]gokalkan.OptionsCert, 0, len(s.urls))

	for _, u := range s.urls {
		cert, err := s.fetchOne(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("fetch CA cert %s: %w", u, err)
		}

		certs = append(certs, gokalkan.OptionsCert{Cert: cert, Type: certType(cert)})
	}

	return certs, nil
}

func (s *Service) fetchOne(ctx context.Context, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	der := body
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	}

	return x509.ParseCertificate(der)
}

// certType определяет CA/Intermediate по стандартным признакам X.509:
// самоподписанный сертификат с CA=true - корневой, иначе - промежуточный.
// NCANODE_CA_URL не различает их явно (единый список), Java-реализация тоже
// определяет тип по содержимому сертификата, а не по URL. Используем
// побайтовое сравнение Issuer/Subject, а не CheckSignatureFrom - у GOST
// сертификатов Go не умеет проверять подпись (неизвестный алгоритм), но
// самоподписанность как признак корневого сертификата это не отменяет.
func certType(cert *x509.Certificate) ckalkan.CertType {
	if cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return ckalkan.CertTypeCA
	}

	return ckalkan.CertTypeIntermediate
}
