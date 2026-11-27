# SPDX-License-Identifier: AGPL-3.0-or-later
# The Go image comes from the Amazon ECR Public copy of Docker's official images,
# pinned to the same index digest Docker Hub serves: Docker Hub limits anonymous
# pulls per address, and the shared CI runners exhaust it.
FROM public.ecr.aws/docker/library/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
# The revision this image was built from, stamped into the binaries so every
# page and contract can report exactly which build is serving it.
ARG SHAUTH_REVISION=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/e6qu/shauth/internal/version.revision=${SHAUTH_REVISION}" -o /out/shauth ./cmd/shauth
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/e6qu/shauth/internal/version.revision=${SHAUTH_REVISION}" -o /out/shauth-migrate ./cmd/shauth-migrate
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/e6qu/shauth/internal/version.revision=${SHAUTH_REVISION}" -o /out/shauth-healthcheck ./cmd/shauth-healthcheck
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/e6qu/shauth/internal/version.revision=${SHAUTH_REVISION}" -o /out/shauth-gateway ./cmd/shauth-gateway

# The Go image comes from the Amazon ECR Public copy of Docker's official images,
# pinned to the same index digest Docker Hub serves: Docker Hub limits anonymous
# pulls per address, and the shared CI runners exhaust it.
FROM public.ecr.aws/docker/library/golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS hydra-build
ARG HYDRA_COMMIT=0b84568fffccf151dc5e6c7955fdfb738555bf4b
ARG HYDRA_SOURCE_SHA256=7ceaae3299780959e8390925732629931f63f20300464d2822d49628eeb3332e
RUN apk add --no-cache patch
WORKDIR /src
RUN wget -O hydra.tar.gz "https://github.com/ory/hydra/archive/${HYDRA_COMMIT}.tar.gz" \
    && echo "${HYDRA_SOURCE_SHA256}  hydra.tar.gz" | sha256sum -c - \
    && mkdir hydra \
    && tar -xzf hydra.tar.gz --strip-components=1 -C hydra
WORKDIR /src/hydra
COPY third_party/hydra-v26.2.0/logout-token-exp.patch /tmp/logout-token-exp.patch
COPY third_party/hydra-v26.2.0/no-sentinel-error-log.patch /tmp/no-sentinel-error-log.patch
RUN patch --forward --fuzz=0 -p1 < /tmp/logout-token-exp.patch \
    && patch --forward --fuzz=0 -p1 < /tmp/no-sentinel-error-log.patch
# Hydra v26.2.0 is the newest upstream release, but its module graph predates
# several security fixes. Pin the repaired transitive modules explicitly so the
# final OAuth server does not retain known vulnerable implementations.
RUN go get \
    github.com/go-jose/go-jose/v3@v3.0.5 \
    github.com/jackc/pgx/v5@v5.13.0 \
    go.opentelemetry.io/otel@v1.47.0 \
    go.opentelemetry.io/otel/sdk@v1.47.0 \
    go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.47.0 \
    golang.org/x/crypto@v0.59.0 \
    golang.org/x/net@v0.63.0 \
    golang.org/x/sys@v0.50.0 \
    golang.org/x/text@v0.44.0 \
    google.golang.org/grpc@v1.85.0 \
    && go mod tidy
COPY third_party/hydra-v26.2.0/go-jose-v3-security.patch /tmp/go-jose-v3-security.patch
COPY third_party/hydra-v26.2.0/pgproto3-v2-security.patch /tmp/pgproto3-v2-security.patch
# These legacy major versions have no upstream security release. Keep their
# module identities and backport the reviewed fixes into the build's vendor
# tree; regression tests exercise the exact code linked into Hydra.
RUN go mod vendor \
    && patch --forward --fuzz=0 -d vendor/github.com/go-jose/go-jose/v3 -p1 < /tmp/go-jose-v3-security.patch \
    && patch --forward --fuzz=0 -d vendor/github.com/jackc/pgproto3/v2 -p1 < /tmp/pgproto3-v2-security.patch \
    && go test -mod=vendor -timeout=120s github.com/go-jose/go-jose/v3 github.com/jackc/pgproto3/v2
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags='-s -w' -o /out/hydra .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/shauth /shauth
COPY --from=build /out/shauth-migrate /shauth-migrate
COPY --from=build /out/shauth-healthcheck /shauth-healthcheck
COPY --from=build /out/shauth-gateway /shauth-gateway
COPY --from=hydra-build /out/hydra /hydra
COPY --from=hydra-build /src/hydra/LICENSE /licenses/hydra/LICENSE
COPY migrations /migrations
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/shauth-healthcheck"]
ENTRYPOINT ["/shauth"]
