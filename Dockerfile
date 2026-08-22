# SPDX-License-Identifier: AGPL-3.0-or-later
FROM golang:1.27.0-alpine AS build
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

FROM golang:1.27.0-alpine AS hydra-build
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
RUN patch --forward --fuzz=0 -p1 < /tmp/logout-token-exp.patch
# Hydra v26.2.0 is the newest upstream release, but its module graph predates
# several security fixes. Pin the repaired transitive modules explicitly so the
# final OAuth server does not retain known vulnerable implementations.
RUN go get \
    github.com/go-jose/go-jose/v3@v3.0.5 \
    github.com/jackc/pgx/v5@v5.9.2 \
    go.opentelemetry.io/otel@v1.43.0 \
    go.opentelemetry.io/otel/sdk@v1.43.0 \
    go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.43.0 \
    golang.org/x/crypto@v0.53.0 \
    golang.org/x/net@v0.56.0 \
    golang.org/x/sys@v0.46.0 \
    golang.org/x/text@v0.39.0 \
    google.golang.org/grpc@v1.82.1 \
    && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/hydra .

FROM gcr.io/distroless/static-debian12:nonroot
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
