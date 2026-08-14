# NCANode-Go

Порт [NCANode](https://github.com/ncanode-kz) (Java) на Go поверх [gokalkan](https://github.com/ncanode-kz/gokalkan) - обёртки над нативной библиотекой KalkanCrypt (pki.gov.kz).

Цель - 100% совместимость по HTTP API (эндпоинты, JSON-контракты, коды ошибок) с оригинальным Java-сервисом.

## Статус

В разработке, по фазам:

- [x] **Phase A** - фундамент: конфигурация (`NCANODE_*`, 1:1 с `application.yml`), роутер с единым конвертом ошибок, `/actuator/health`, загрузка/кэширование CA-сертификатов (с fail-fast стартом, как в Java), кэширование CRL, сборка `CertificateInfo`.
- [ ] **Phase B** - `/cms/*`, `/x509/*`, `/pkcs12/*`, `/jwt/*`
- [ ] **Phase C** - `/xml/*`, `/wsse/*`
- [ ] **Phase D** - `/pdf/*`
- [ ] **Phase E** - тестовое покрытие ≥90%

## Запуск

Требует нативную библиотеку `libkalkancryptwr-64.so` (см. README [gokalkan](https://github.com/ncanode-kz/gokalkan)) и CGO.

```sh
go run ./cmd/ncanode
```

Конфигурация - через переменные окружения `NCANODE_*` (см. `internal/config`), имена и дефолты соответствуют `application.yml` оригинального NCANode.

## Тесты

```sh
go test ./...
```

Фикстуры (`internal/testdata/certs`) - тестовые GOST-сертификаты pki.gov.kz (test-контур), не боевые ключи.
