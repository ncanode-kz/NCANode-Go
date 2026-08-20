# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends curl openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1 GOOS=linux GOARCH=amd64
RUN go build -o /out/ncanode ./cmd/ncanode

# KalkanCrypt (libkalkancryptwr-64.so) - закрытый нативный SDK от pki.gov.kz,
# нужен на этапе рантайма (gokalkan грузит его через dlopen, см. AGENTS.md).
# URL передаётся через BuildKit secret, а не ARG/ENV, чтобы он не осел в
# истории слоёв образа - в образе остаётся только сама библиотека.
RUN --mount=type=secret,id=kalkan_so_url \
    curl -sSfL -o /out/libkalkancryptwr-64.so "$(cat /run/secrets/kalkan_so_url)"

# KalkanCrypt проверяет цепочку не только через сертификаты из WithCerts, но
# и опирается на системное доверенное хранилище - без этого шага
# X509LoadCertificateFromFile для GOST-2022 root/intermediate падает с
# "certificate expired or not yet valid" даже для валидных сертификатов
# (эмпирически подтверждено при отладке CI). root_gost_2022.cer/
# nca_gost_2022.cer - публичные сертификаты с pki.gov.kz, те же, что
# приложение и так тянет по умолчанию (см. internal/config.CAConfig.URLs).
RUN curl -sSfL -o /out/root_gost_2022.cer http://pki.gov.kz/cert/root_gost_2022.cer \
    && curl -sSfL -o /out/nca_gost_2022.cer http://pki.gov.kz/cert/nca_gost_2022.cer \
    && openssl x509 -inform DER -in /out/root_gost_2022.cer -out /out/root_gost_2022.crt \
    && openssl x509 -inform DER -in /out/nca_gost_2022.cer -out /out/nca_gost_2022.crt

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget libpcsclite1 libltdl7 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/ncanode /app/ncanode
COPY --from=builder /out/libkalkancryptwr-64.so /usr/lib/libkalkancryptwr-64.so
RUN ldconfig

COPY --from=builder /out/root_gost_2022.crt /out/nca_gost_2022.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

RUN mkdir /app/cache
VOLUME /app/cache

EXPOSE 14579
ENTRYPOINT ["/app/ncanode"]

HEALTHCHECK --interval=20s --timeout=30s --retries=7 \
    CMD wget -O - http://127.0.0.1:14579/actuator/health | grep -v DOWN || exit 1
