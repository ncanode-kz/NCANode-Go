# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends curl \
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

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget libpcsclite1 libltdl7 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/ncanode /app/ncanode
COPY --from=builder /out/libkalkancryptwr-64.so /usr/lib/libkalkancryptwr-64.so
RUN ldconfig

RUN mkdir /app/cache
VOLUME /app/cache

EXPOSE 14579
ENTRYPOINT ["/app/ncanode"]

HEALTHCHECK --interval=20s --timeout=30s --retries=7 \
    CMD wget -O - http://127.0.0.1:14579/actuator/health | grep -v DOWN || exit 1
