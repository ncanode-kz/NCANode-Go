# NCANode-Go

Порт [NCANode](https://github.com/ncanode-kz) (Java) на Go поверх [gokalkan](https://github.com/ncanode-kz/gokalkan) - обёртки над нативной библиотекой KalkanCrypt (pki.gov.kz).

Цель - 100% совместимость по HTTP API (эндпоинты, JSON-контракты, коды ошибок) с оригинальным Java-сервисом.

## Статус

В разработке, по фазам:

- [x] **Phase A** - фундамент: конфигурация (`NCANODE_*`, 1:1 с `application.yml`), роутер с единым конвертом ошибок, `/actuator/health`, загрузка/кэширование CA-сертификатов (с fail-fast стартом, как в Java), кэширование CRL, сборка `CertificateInfo`.
- [x] **Phase B** - `/cms/sign`, `/cms/sign/add`, `/cms/verify`, `/cms/extract`, `/x509/info`, `/x509/sign`, `/x509/verify`, `/pkcs12/info`, `/pkcs12/aliases`, `/jwt/encode`, `/jwt/decode`.
- [x] **Phase C** - `/xml/sign`, `/xml/verify`, `/wsse/sign`, `/wsse/verify`.
- [x] **Phase D** - `/pdf/sign`, `/pdf/verify`.
- [x] **Phase E** - тестовое покрытие ≥90% (90.06% суммарно, см. `## Тесты`).

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

### Известные ограничения (Phase D)

- `PdfSignerInfo.digestAlgorithm` (OID алгоритма хэширования CMS, отдельно от
  `signatureAlgorithm`) не заполняется - gokalkan не извлекает это поле из
  подписи структурно.
- `contactInfo`/`reason`/`location` в ответе `/pdf/verify` при отсутствии
  значения опускаются из JSON (`omitempty`), тогда как Java явно пишет
  `null` - разница в форме, не в семантике для типичных JSON-клиентов.

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

## API-документация

Swagger UI: `http://localhost:14579/swagger-ui.html`
Сырая OpenAPI-спека (JSON): `http://localhost:14579/v3/api-docs`

Те же пути, что и у springdoc-openapi в Java-версии. Спека (`internal/openapi/openapi.json`)
сконвертирована из `openapi.yml` оригинального NCANode - paths/schemas 1:1
совпадают с Go DTO (`internal/dto`), обрезаны только actuator-эндпоинты,
которых нет в Go-версии (`/actuator`, `/actuator/health/**`).

Ассеты Swagger UI (`internal/openapi/static/`) полностью завёрнуты в
бинарник (`go:embed`) и раздаются с `/swagger-ui/*` - без обращения к CDN в
рантайме. Файлы взяты из `org.webjars:swagger-ui:5.11.8` (та же версия, что
тянет springdoc-openapi в Java NCANode, лицензия Apache-2.0).

## Тесты

```sh
go test ./...
```

Фикстуры (`internal/testdata/certs`) - тестовые GOST-сертификаты pki.gov.kz (test-контур), не боевые ключи.

Суммарное покрытие (statement coverage по всем пакетам, включая перекрёстное
покрытие через `internal/testutil` и `cmd/ncanode`, посчитанное через
`go test ./... -coverpkg=./...`) - **90.06%**. `main()` в `cmd/ncanode`
намеренно не покрыт юнит-тестами - это тонкая связующая обвязка
(`os.Exit`, `http.Server.ListenAndServe`), которую тестировать модульно не
имеет смысла; вся содержательная логика вынесена в тестируемые
`bootstrapCA`/`bootstrapCRL`/`newHandler` в том же пакете.

Интеграционные interop-тесты со сверкой против живого Java NCANode (за
build tag `oracle`, не входят в обычный `go test ./...`):

```sh
go test -tags oracle ./...
```
