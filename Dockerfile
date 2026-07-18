# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS builder

WORKDIR /src
ENV CGO_ENABLED=0
ARG VERSION=container
ARG COMMIT=unavailable
ARG BUILD_DATE=1970-01-01T00:00:00Z

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN GOOS=linux go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" -o /out/byoo ./cmd/byoo

FROM debian:bookworm-slim AS runtime
ARG VERSION=container
ARG COMMIT=unavailable
ARG BUILD_DATE=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.version=$VERSION org.opencontainers.image.revision=$COMMIT org.opencontainers.image.created=$BUILD_DATE

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 byoo \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home byoo \
    && install --directory --mode=0700 --owner=byoo --group=byoo /data \
    && install --directory --mode=0755 /etc/byoo \
    && install --directory --mode=0755 /usr/share/doc/byoo

COPY --from=builder /out/byoo /usr/local/bin/byoo
COPY --from=builder /src/LICENSE /usr/share/doc/byoo/LICENSE
COPY --from=builder /src/THIRD_PARTY_NOTICES /usr/share/doc/byoo/THIRD_PARTY_NOTICES
COPY --from=builder /src/deploy/railway.yaml /etc/byoo/railway.yaml

WORKDIR /data
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

USER byoo:byoo
CMD ["byoo", "serve", "--listen", "0.0.0.0:8080", "--data-dir", "/data"]
