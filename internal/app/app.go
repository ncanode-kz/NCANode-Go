// Package app собирает вместе общие зависимости (конфиг, CA/CRL/OCSP
// сервисы, единственный на процесс gokalkan-клиент) и раздаёт их пакетам
// internal/service/*.
package app

import (
	"fmt"
	"sync"

	"github.com/ncanode-kz/NCANode-Go/internal/caservice"
	"github.com/ncanode-kz/NCANode-Go/internal/config"
	"github.com/ncanode-kz/NCANode-Go/internal/crlservice"
	"github.com/ncanode-kz/NCANode-Go/internal/ocspservice"
	"github.com/ncanode-kz/gokalkan"
)

type App struct {
	Config config.Config

	CA   *caservice.Service
	CRL  *crlservice.Service
	OCSP *ocspservice.Service

	// Shared - ЕДИНСТВЕННЫЙ на весь процесс gokalkan-клиент. Это не
	// оптимизация, а необходимость: нативная библиотека KalkanCrypt хранит
	// своё состояние (в т.ч. указатель на таблицу функций kc_funcs) в
	// ГЛОБАЛЬНЫХ C-переменных процесса, а не per-handle. Создание второго
	// независимого *gokalkan.Client и его Close() (который вызывает
	// KC_Finalize/dlclose) рушит состояние ПЕРВОГО, уже работающего клиента -
	// экспериментально подтверждено (verify после закрытия отдельного
	// sign-клиента начинает падать с "library not initialized"). Поэтому
	// вместо клиента-на-запрос используется один клиент на всё приложение,
	// а атомарность многошаговых операций с загрузкой ключа (LoadKeyStore +
	// Sign/AddSigner) обеспечивается SigningMu.
	Shared *gokalkan.Client

	// SigningMu - сериализует операции, которым нужно грузить "текущий" ключ
	// (LoadKeyStore держит только один активный ключ на клиента). Каждый
	// sign-хендлер должен держать эту блокировку на всё время своей
	// последовательности LoadKeyStore->Sign[->AddSigner...], чтобы конкурентные
	// запросы не перезатёрли друг другу загруженный ключ. Операции без
	// загрузки ключа (verify/info/validate) в этой блокировке не нуждаются -
	// они уже сериализованы на уровне отдельного нативного вызова
	// (см. мьютекс внутри ckalkan.Client).
	SigningMu sync.Mutex
}

func New(cfg config.Config, ca *caservice.Service, crl *crlservice.Service, ocsp *ocspservice.Service) (*App, error) {
	shared, err := gokalkan.NewClient(
		gokalkan.WithTSP(cfg.TSP.URL),
		gokalkan.WithOCSP(ocsp.URL()),
		gokalkan.WithCerts(ca.Certs()),
	)
	if err != nil {
		return nil, fmt.Errorf("create shared kalkan client: %w", err)
	}

	return &App{
		Config: cfg,
		CA:     ca,
		CRL:    crl,
		OCSP:   ocsp,
		Shared: shared,
	}, nil
}

func (a *App) Close() error {
	return a.Shared.Close()
}
