FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /mcp-gateway ./cmd/mcp-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /mcp-gateway /usr/local/bin/mcp-gateway
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/mcp-gateway"]
