# NCANode-Go

Порт [NCANode](https://github.com/ncanode-kz) (Java) на Go поверх [gokalkan](https://github.com/ncanode-kz/gokalkan) - обёртки над нативной библиотекой KalkanCrypt (pki.gov.kz).

Цель - 100% совместимость по HTTP API (эндпоинты, JSON-контракты, коды ошибок) с оригинальным Java-сервисом.

## Статус

В разработке, по фазам:

- [x] **Phase A** - фундамент: конфигурация (`NCANODE_*`, 1:1 с `application.yml`), роутер с единым конвертом ошибок, `/actuator/health`, загрузка/кэширование CA-сертификатов (с fail-fast стартом, как в Java), кэширование CRL, сборка `CertificateInfo`.
- [x] **Phase B** - `/cms/sign`, `/cms/sign/add`, `/cms/verify`, `/cms/extract`, `/x509/info`, `/x509/sign`, `/x509/verify`, `/pkcs12/info`, `/pkcs12/aliases`, `/jwt/encode`, `/jwt/decode`.
- [x] **Phase C** - `/xml/sign`, `/xml/verify`, `/wsse/sign`, `/wsse/verify`.
- [ ] **Phase D** - `/pdf/*`
- [ ] **Phase E** - тестовое покрытие ≥90%

### Известные ограничения (Phase B)

- `signAlg` в `CertificateInfo` - короткое имя алгоритма подтверждено сверкой
  с Java только для `ECGOST3410-2015-512`; для прочих OID возвращается сам
  OID вместо человекочитаемого имени (см. `certservice.signAlgByOID`).
- `TspInfo` в ответах `/cms/verify` заполняет только `genTime` (парсится из
  текстового отчёта нативной библиотеки); `serialNumber`/`policy`/`tsa`/`hash`
  пока не извлекаются - gokalkan не отдаёт их структурно.
- `/pkcs12/aliases` не умеет перечислять несколько алиасов внутри одного
  PKCS12 (нативная библиотека/gokalkan работают с единственным дефолтным
  алиасом) - корректно для типичного PKCS12 с одним ключом.
- `SignerRequest.keyAlias` пока не используется - см. предыдущий пункт.
- `revocationTime` в `Revocation` всегда `null` - gokalkan сообщает только
  сам факт отзыва, не точное время.

### Известные ограничения (Phase C)

- Порядок подписантов в ответе `/xml/verify` (от последней подписи к первой)
  и single-signer-only поведение `/wsse/verify` воспроизведены и сверены с
  Java, но основаны на эмпирически подтверждённой (не документированной)
  индексации `KC_getCertFromXML` - если нативная библиотека сменит поведение
  между версиями, это может незаметно разойтись.

### Важная архитектурная особенность

Нативная библиотека KalkanCrypt хранит состояние в глобальных для процесса
C-переменных, а не per-handle - создание второго независимого
`gokalkan.Client` и его `Close()` рушит состояние уже работающего клиента
(экспериментально обнаружено при разработке Phase B). Поэтому в приложении
используется **один** `gokalkan.Client` на весь процесс (`app.App.Shared`), а
атомарность многошаговых операций с загрузкой ключа обеспечивается
`app.App.SigningMu` - все sign-эндпоинты сериализованы этим мьютексом.

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
