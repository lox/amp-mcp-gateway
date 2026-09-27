# syntax=docker/dockerfile:1
FROM node:22.20.0-bookworm-slim AS styles
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY internal ./internal
RUN npm run build:css

FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=styles /src/internal/webui/assets/ui.css ./internal/webui/assets/ui.css
# Retain dependencies and compiled packages when source changes invalidate this layer.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /mcp-gateway ./cmd/mcp-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /mcp-gateway /usr/local/bin/mcp-gateway
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/mcp-gateway"]
