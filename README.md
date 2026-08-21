# NCANode-Go

⭐ Go-порт [NCANode](https://github.com/ncanode-kz/NCANode) — сервера для работы с Электронно Цифровой Подписью (ЭЦП) РК

---

![CI](https://github.com/ncanode-kz/NCANode-Go/actions/workflows/ci.yml/badge.svg)
[![Release](https://img.shields.io/github/v/release/ncanode-kz/NCANode-Go?include_prereleases)](https://github.com/ncanode-kz/NCANode-Go/releases)
[![codecov](https://codecov.io/gh/ncanode-kz/NCANode-Go/graph/badge.svg)](https://codecov.io/gh/ncanode-kz/NCANode-Go)
![License:MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

> ⚠️ **Экспериментальный проект.** Это независимый порт эталонной Java-версии
> NCANode на Go, разрабатывается на данный момент одним человеком и не
> проходил боевую эксплуатацию. Перед использованием в продакшене
> самостоятельно проверьте совместимость с вашим окружением и типами
> подписей.

## Возможности

- Работа с API посредством JSON, полностью совместим по контракту с
  [оригинальным NCANode](https://github.com/ncanode-kz/NCANode) (Java)
- Подпись и проверка XML данных с помощью xmldsig
- Подпись и проверка Wsse для [SmartBridge](https://sb.egov.kz/)
- Подпись и проверка PDF
- Поддержка работы с CMS ([Cryptographic Message Syntax](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax)),
  включая добавление подписи к уже существующему CMS и извлечение подписанных данных
- Поддержка TSP-меток в CMS
- Проверка валидности сертификатов (включая цепочку доверия), OCSP и CRL
- Работа с PKCS12-хранилищами (информация о ключе, алиасы)
- Кодирование/декодирование JWT
- Поддержка новых ЭЦП (ГОСТ 2015) и новых CRL
- Swagger UI и OpenAPI-спека из коробки, без обращения к CDN
- Тестовое покрытие ≥90%

## Пример

Пример запроса (запрос информации о сертификате):

```json
{
  "certificate": "MIIFdzCCBF+gAwIBAgIUb...",
  "withCertificateInfo": true
}
```

Пример ответа:

```json
{
  "valid": true,
  "certificates": [
    {
      "certificate": "MIIFdzCCBF+gAwIBAgIUb...",
      "certInfo": {
        "subject": { "commonName": "ИВАНОВ ИВАН ИВАНОВИЧ", "...": "..." },
        "issuer": { "commonName": "..." },
        "validFrom": "2025-01-01T00:00:00",
        "validTo": "2026-01-01T00:00:00"
      },
      "revocation": { "revoked": false }
    }
  ]
}
```

## Документация

Swagger UI: `http://localhost:14579/swagger-ui/`

Сырая OpenAPI-спека (JSON): `http://localhost:14579/v3/api-docs`

Спека (`internal/openapi/openapi.json`) сконвертирована из `openapi.yml`
оригинального NCANode — paths/schemas 1:1 совпадают с Go DTO (`internal/dto`).

## Требования

Проект использует [gokalkan](https://github.com/ncanode-kz/gokalkan) —
обёртку над нативной библиотекой **KalkanCrypt** (`libkalkancryptwr-64.so`).
SDK не лежит в открытом доступе, его нужно запросить у
[pki.gov.kz](https://pki.gov.kz/developers/).

Библиотека собрана только под **x86_64** — на ARM (в т.ч. Apple Silicon)
проект не соберётся и не запустится.

`go.mod` временно содержит `replace github.com/ncanode-kz/gokalkan => ../gokalkan`,
поэтому рядом с этим репозиторием нужен локальный чекаут
[gokalkan](https://github.com/ncanode-kz/gokalkan).

## Запуск

### Docker

Образ уже включает KalkanCrypt SDK — доустанавливать ничего не нужно (только
**linux/amd64**, см. [«Требования»](#требования)):

```sh
docker run -p 14579:14579 -v ncanode-cache:/app/cache ghcr.io/ncanode-kz/ncanode-go:latest
```

Другие теги — на странице [Releases](https://github.com/ncanode-kz/NCANode-Go/releases)
(например, `ghcr.io/ncanode-kz/ncanode-go:v1.2.3`).

### Из исходников

```sh
go run ./cmd/ncanode
```

Конфигурация — через переменные окружения `NCANODE_*` (см. `internal/config`),
имена и дефолты соответствуют `application.yml` оригинального NCANode.

После запуска сервис доступен на `http://localhost:14579`.

## Тесты

```sh
go test ./...
```

Фикстуры (`internal/testdata/certs`) — тестовые GOST-сертификаты pki.gov.kz
(test-контур), не боевые ключи.

Интеграционные interop-тесты со сверкой против живого Java NCANode (за build
tag `oracle`, не входят в обычный `go test ./...`):

```sh
go test -tags oracle ./...
```

## Детали реализации совместимости

Ряд полей и поведений сверен с эталонной Java-версией не через тривиальный
вызов KalkanCrypt, а отдельной логикой на стороне Go — ниже основные места,
если понадобится в них разобраться:

- **`signAlg` в `CertificateInfo`** — таблица OID→имя (`certservice.signAlgByOID`)
  расширена по тому же источнику истины, что использует и сама Java в
  рантайме (provider-jar `knca_provider_jce_kalkan`). Покрывает RSA-семейство
  (MD2/MD4/MD5/SHA1/SHA224/SHA256/SHA384/SHA512WithRSAEncryption), ГОСТ Р
  34.10-94/2001/2004 и ГОСТ Р 34.10-2015 (256/512). Для OID вне этой таблицы
  возвращается сам OID — как и в Java-провайдере для неизвестных алгоритмов.
- **`TspInfo` в `/cms/verify`** — разбирается структурно (ASN.1, RFC 3161) из
  самого CMS, независимо от KalkanCrypt, тем же способом, что и у Java
  (`kz.gov.pki.kalkan.tsp`, см. `internal/tsp`): `serialNumber`/`genTime`/
  `policy`/`hash` заполняются всегда, когда в CMS есть TSP-токен.
  `tspHashAlgorithm` использует ту же таблицу, что и
  `KalkanUtil.getHashingAlgorithmByOID` в Java, поэтому у ГОСТ-2015-подписей
  это поле, как и в Java, остаётся пустым. `tsa` не извлекается — это
  опциональное поле TSTInfo, которое тестовый TSA pki.gov.kz не заполняет.
- **`/pkcs12/aliases`** — нативная `KC_GetCertificatesList` для хранилища,
  загруженного из PKCS12, возвращает `KCR_NOTOKENFOUND` ("no token found"):
  она реализована только для аппаратных токенов (KAZTOKEN/eToken/JaCarta и
  т.п.), как и в примере из SDK (`test.cpp`). Вызов подключён
  (`gokalkan.Client.ListCertificateAliases`) и будет работать при поддержке
  токенов, но для PKCS12 (основной случай в экосистеме pki.gov.kz)
  используется единственный дефолтный алиас `""`. `SignerRequest.keyAlias`
  прокидывается в `KC_LoadKeyStore` (см. `kalkanutil.LoadSigner`), для
  типичного PKCS12 с одним ключом дефолтного алиаса этого достаточно.
- **`revocationTime` в `Revocation`** заполняется и для OCSP, и для CRL. Для
  OCSP — парсится из текстового отчёта `X509ValidateCertificate` (строка
  `Revocation Time: ...`). Для CRL — структурным ASN.1-разбором закэшированного
  CRL-файла (`internal/certservice/crlentry.go`, в обход
  `crypto/x509.ParseRevocationList` — у неё есть доп. проверка "inner/outer
  signature algorithm", которая не проходит на живых ГОСТ-CRL pki.gov.kz),
  откуда же берётся и точная причина отзыва (`reason`) в стиле
  `java.security.cert.CRLReason` (`KEY_COMPROMISE`, `CERTIFICATE_HOLD` и
  т.д.). Семантика `reason` приведена в соответствие с Java: для OCSP всегда
  `"OK"` (даже когда отозван), для CRL при `revoked=false` поле не пишется
  вовсе (JSON `null`) — `dto.Revocation.Reason` сделан указателем, чтобы
  отличить это от пустой строки.
- **Порядок подписантов** в ответе `/xml/verify` (от последней подписи к
  первой) и single-signer-only поведение `/wsse/verify` сверены с Java, но
  основаны на эмпирически подтверждённой (не документированной) индексации
  `KC_getCertFromXML` — если нативная библиотека сменит поведение между
  версиями, это может незаметно разойтись.
- **`PdfSignerInfo.digestAlgorithm`** (OID алгоритма хэширования CMS, отдельно
  от `signatureAlgorithm`) заполняется структурным ASN.1-разбором detached CMS
  каждой подписи (`digitorus/pkcs7`, без обращения к KalkanCrypt) — тем же
  способом, что и `si.getDigestAlgOID()` в Java `PdfService`. Фолбэк
  `"unknown"` — тот же, что и в Java, на случай если CMS не распарсился.
  `contactInfo`/`reason`/`location` в ответе `/pdf/verify` явно `null` в
  JSON, когда соответствующий ключ подписи отсутствует в PDF (не то же
  самое, что пустая строка), как и у Java.
- **Один `gokalkan.Client` на процесс.** Нативная библиотека KalkanCrypt
  хранит состояние в глобальных для процесса C-переменных, а не per-handle —
  создание второго независимого `gokalkan.Client` и его `Close()` рушит
  состояние уже работающего клиента. Поэтому в приложении используется
  единственный `gokalkan.Client` на весь процесс (`app.App.Shared`), а
  атомарность многошаговых операций с загрузкой ключа обеспечивается
  `app.App.SigningMu` — все sign-эндпоинты сериализованы этим мьютексом.

## Лицензия

Проект лицензирован под лицензией [MIT](LICENSE)
