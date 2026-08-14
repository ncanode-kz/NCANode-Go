// Command ncanode - HTTP-сервис, порт NCANode (Java) на Go поверх gokalkan.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/caservice"
	"github.com/ncanode-kz/NCANode-Go/internal/config"
	"github.com/ncanode-kz/NCANode-Go/internal/crlservice"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/ocspservice"
	"github.com/ncanode-kz/NCANode-Go/internal/service/cms"
	"github.com/ncanode-kz/NCANode-Go/internal/service/jwt"
	"github.com/ncanode-kz/NCANode-Go/internal/service/pdf"
	"github.com/ncanode-kz/NCANode-Go/internal/service/pkcs12"
	"github.com/ncanode-kz/NCANode-Go/internal/service/wsse"
	x509svc "github.com/ncanode-kz/NCANode-Go/internal/service/x509"
	xmlsvc "github.com/ncanode-kz/NCANode-Go/internal/service/xml"
)

func main() {
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ca := caservice.New(cfg.CA.URLs, cfg.CA.TTL)
	if err := ca.Bootstrap(ctx); err != nil {
		// Соответствует поведению Java NCANode: без валидных CA-сертификатов
		// сервис не может строить доверенные цепочки, поэтому падает сразу
		// при старте, а не отдаёт частично рабочий API (см. System.exit(32)
		// в kz.ncanode.service.CaService).
		slog.Error("failed to bootstrap CA certificates", "error", err)
		os.Exit(32)
	}
	ca.StartBackgroundRefresh(ctx)
	slog.Info("CA certificates loaded", "count", len(ca.Certs()))

	crl := crlservice.New(cfg.CacheDir, cfg.CRL.Enabled, cfg.CRL.URLs, cfg.CRL.TTL, cfg.CRL.DeltaURLs, cfg.CRL.DeltaTTL)
	if err := crl.Bootstrap(ctx); err != nil {
		// В отличие от CA-сертификатов, CRL - не блокер старта (см. Java
		// CrlService: логирует и продолжает, ревокацию можно проверить позже
		// после фонового обновления).
		slog.Error("failed to bootstrap CRL cache, will retry in background", "error", err)
	}
	crl.StartBackgroundRefresh(ctx)

	ocsp := ocspservice.New(cfg.OCSPURL)

	a, err := app.New(cfg, ca, crl, ocsp)
	if err != nil {
		slog.Error("failed to initialize KalkanCrypt client", "error", err)
		os.Exit(1)
	}
	defer a.Close() //nolint:errcheck

	srv := httpapi.New(cfg.Debug)
	srv.RegisterHealth()
	cms.RegisterRoutes(srv, a)
	x509svc.RegisterRoutes(srv, a)
	pkcs12.RegisterRoutes(srv, a)
	jwt.RegisterRoutes(srv, a)
	xmlsvc.RegisterRoutes(srv, a)
	wsse.RegisterRoutes(srv, a)
	pdf.RegisterRoutes(srv, a)

	httpServer := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: srv.Handler(),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
	}()

	slog.Info("starting ncanode", "port", cfg.Port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
