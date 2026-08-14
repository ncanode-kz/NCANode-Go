// Package crlservice - аналог kz.ncanode.service.CrlService: скачивает и
// кэширует на диск CRL (полные и delta списки), с фоновым TTL-обновлением.
// gokalkan.ValidateCertCRL принимает путь к локальному файлу CRL (нативная
// библиотека сама файлы не скачивает), поэтому сервис хранит их как файлы в
// NCANODE_CACHE_DIR, а не только в памяти.
package crlservice

import (
	"context"
	"crypto/sha1" //nolint:gosec // только для имени файла кэша, не для крипто-операций
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Service struct {
	enabled bool

	fullURLs  []string
	fullTTL   time.Duration
	deltaURLs []string
	deltaTTL  time.Duration

	cacheDir   string
	httpClient *http.Client

	mu         sync.RWMutex
	fullPaths  []string
	deltaPaths []string
}

func New(cacheDir string, enabled bool, fullURLs []string, fullTTL time.Duration, deltaURLs []string, deltaTTL time.Duration) *Service {
	return &Service{
		enabled:    enabled,
		fullURLs:   fullURLs,
		fullTTL:    fullTTL,
		deltaURLs:  deltaURLs,
		deltaTTL:   deltaTTL,
		cacheDir:   cacheDir,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *Service) Enabled() bool { return s.enabled }

// Bootstrap загружает начальный набор CRL. В отличие от caservice.Bootstrap
// ошибка здесь не фатальна (как и в Java - CrlService логирует и продолжает,
// не роняя старт сервиса), но возвращается вызывающему коду на случай, если
// он захочет её залогировать.
func (s *Service) Bootstrap(ctx context.Context) error {
	if !s.enabled {
		return nil
	}

	fullErr := s.refreshFull(ctx)
	deltaErr := s.refreshDelta(ctx)

	if fullErr != nil {
		return fullErr
	}

	return deltaErr
}

func (s *Service) StartBackgroundRefresh(ctx context.Context) {
	if !s.enabled {
		return
	}

	if s.fullTTL > 0 {
		go s.refreshLoop(ctx, s.fullTTL, s.refreshFull)
	}
	if s.deltaTTL > 0 && len(s.deltaURLs) > 0 {
		go s.refreshLoop(ctx, s.deltaTTL, s.refreshDelta)
	}
}

func (s *Service) refreshLoop(ctx context.Context, ttl time.Duration, fn func(context.Context) error) {
	ticker := time.NewTicker(ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				slog.Error("crl refresh failed, keeping previous cache", "error", err)
			}
		}
	}
}

// FullPaths/DeltaPaths - пути к закэшированным на диске CRL-файлам (по одному
// на каждый сконфигурированный URL), для перебора в certservice.
func (s *Service) FullPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, len(s.fullPaths))
	copy(out, s.fullPaths)

	return out
}

func (s *Service) DeltaPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, len(s.deltaPaths))
	copy(out, s.deltaPaths)

	return out
}

func (s *Service) refreshFull(ctx context.Context) error {
	paths, err := s.downloadAll(ctx, s.fullURLs, "full")
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.fullPaths = paths
	s.mu.Unlock()

	return nil
}

func (s *Service) refreshDelta(ctx context.Context) error {
	paths, err := s.downloadAll(ctx, s.deltaURLs, "delta")
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.deltaPaths = paths
	s.mu.Unlock()

	return nil
}

func (s *Service) downloadAll(ctx context.Context, urls []string, kind string) ([]string, error) {
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	paths := make([]string, 0, len(urls))

	for _, u := range urls {
		path, err := s.downloadOne(ctx, u, kind)
		if err != nil {
			return nil, fmt.Errorf("download %s crl %s: %w", kind, u, err)
		}

		paths = append(paths, path)
	}

	return paths, nil
}

func (s *Service) downloadOne(ctx context.Context, url, kind string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return "", fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	sum := sha1.Sum([]byte(url)) //nolint:gosec
	path := filepath.Join(s.cacheDir, fmt.Sprintf("%s-%s.crl", kind, hex.EncodeToString(sum[:8])))

	if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec
		return "", err
	}

	return path, nil
}
