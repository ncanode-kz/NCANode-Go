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

- `signAlg` в `CertificateInfo` - таблица OID→имя (`certservice.signAlgByOID`)
  расширена декомпиляцией байткода того же provider-jar
  (`knca_provider_jce_kalkan-0.7.5.jar`), который использует эталонный Java
  NCANode - то есть тот же источник истины, что и у самой Java в рантайме, не
  живая сверка. Покрывает RSA-семейство (MD2/MD4/MD5/SHA1/SHA224/SHA256/
  SHA384/SHA512WithRSAEncryption), ГОСТ Р 34.10-94/2001/2004 и ГОСТ Р
  34.10-2015 (256/512). Для OID вне этой таблицы по-прежнему возвращается сам
  OID - как и в Java-провайдере для неизвестных алгоритмов.
- `TspInfo` в ответах `/cms/verify` разбирается структурно (ASN.1, RFC 3161) из
  самого CMS - независимо от KalkanCrypt, тем же способом, что и у Java
  (`kz.gov.pki.kalkan.tsp`, см. `internal/tsp`): `serialNumber`/`genTime`/
  `policy`/`hash` заполняются всегда, когда в CMS есть TSP-токен.
  `tspHashAlgorithm` использует ту же (сознательно неполную - без ГОСТ-2015)
  таблицу, что и `KalkanUtil.getHashingAlgorithmByOID` в Java, поэтому у
  современных ГОСТ-2015-подписей это поле, как и в Java, остаётся пустым.
  `tsa` не извлекается (это опциональное поле TSTInfo, которое тестовый TSA
  pki.gov.kz не заполняет).
- `/pkcs12/aliases` эмпирически подтверждено: нативная `KC_GetCertificatesList`
  для хранилища, загруженного из PKCS12, возвращает ошибку `KCR_NOTOKENFOUND`
  ("no token found") - она реализована только для аппаратных токенов
  (KAZTOKEN/eToken/JaCarta и т.п.), как и в примере из SDK (`test.cpp`).
  Вызов подключён (`gokalkan.Client.ListCertificateAliases`) и будет работать,
  если понадобится поддержка токенов, но для PKCS12 (основной случай в
  экосистеме pki.gov.kz) используется прежний единственный дефолтный алиас `""`.
- `SignerRequest.keyAlias` теперь прокидывается в `KC_LoadKeyStore` (см.
  `kalkanutil.LoadSigner`), но из-за предыдущего пункта эффект от этого
  ограничен: для типичного PKCS12 с одним ключом дефолтного алиаса достаточно.
- `revocationTime` в `Revocation` заполняется и для OCSP, и для CRL. Для
  OCSP - парсится из текстового отчёта `X509ValidateCertificate` (строка
  `Revocation Time: ...`, тем же способом, что и `TspInfo.genTime` раньше).
  Для CRL - структурным ASN.1-разбором закэшированного CRL-файла
  (`internal/certservice/crlentry.go`, в обход `crypto/x509.ParseRevocationList` -
  у неё есть доп. проверка "inner/outer signature algorithm", которая не
  проходит на живых ГОСТ-CRL pki.gov.kz, хотя сама структура парсится
  корректно), откуда же берётся и точная причина отзыва (`reason`) в стиле
  `java.security.cert.CRLReason` (`KEY_COMPROMISE`, `CERTIFICATE_HOLD` и т.д.).
  Заодно приведена в соответствие семантика `reason`: для OCSP Java всегда
  пишет `"OK"` (даже когда отозван - `revocationReason` там в JSON не
  попадает вообще), для CRL при `revoked=false` Java не пишет это поле совсем
  (JSON `null`) - `dto.Revocation.Reason` стал указателем, чтобы это отличить
  от пустой строки.

### Известные ограничения (Phase C)

- Порядок подписантов в ответе `/xml/verify` (от последней подписи к первой)
  и single-signer-only поведение `/wsse/verify` воспроизведены и сверены с
  Java, но основаны на эмпирически подтверждённой (не документированной)
  индексации `KC_getCertFromXML` - если нативная библиотека сменит поведение
  между версиями, это может незаметно разойтись.

### Известные ограничения (Phase D)

- `PdfSignerInfo.digestAlgorithm` (OID алгоритма хэширования CMS, отдельно от
  `signatureAlgorithm`) заполняется структурным ASN.1-разбором detached CMS
  каждой подписи (`digitorus/pkcs7`, без обращения к KalkanCrypt) - тем же
  способом, что и `si.getDigestAlgOID()` в Java `PdfService`. Фолбэк
  `"unknown"` - тот же, что и в Java, на случай если CMS не распарсился.
- `contactInfo`/`reason`/`location` в ответе `/pdf/verify` теперь явно `null`
  в JSON, когда соответствующий ключ подписи отсутствует в PDF (не то же
  самое, что пустая строка - `gokalkan.PDFSignerInfo` различает эти случаи
  через `pdf.Value.IsNull()`), как и у Java.

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

`go.mod` временно содержит `replace github.com/ncanode-kz/gokalkan => ../gokalkan` -
часть исправлений (алиасы PKCS12, `revocationTime`, `LoadKeyStore` с
alias) пока не опубликованы отдельной версией gokalkan. Понадобится
локальный чекаут `../gokalkan` рядом с этим репозиторием; после публикации
новой версии gokalkan replace нужно будет убрать и обновить версию в `require`.

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
