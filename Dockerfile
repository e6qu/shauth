# SPDX-License-Identifier: AGPL-3.0-or-later
FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/shauth ./cmd/shauth
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/shauth-migrate ./cmd/shauth-migrate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/shauth /shauth
COPY --from=build /out/shauth-migrate /shauth-migrate
COPY migrations /migrations
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/shauth"]
