# ReviewBench image for Amp Review; see docs/reviewbench.md.
# Build from the repository root:
#   docker build --platform linux/amd64 -f cmd/reviewbench-agent/Dockerfile -t amp-review-bench .
FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /reviewbench-agent ./cmd/reviewbench-agent

FROM node:22.20.0-bookworm-slim AS amp-cli
# Same pinned CLI as the gateway image.
RUN npm install --prefix /amp --no-audit --no-fund @ampcode/cli@0.0.1793995239-gedfe82 \
    && /amp/node_modules/@ampcode/cli/bin/amp --version

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git ripgrep \
    && rm -rf /var/lib/apt/lists/*
COPY --from=amp-cli /amp/node_modules/@ampcode/cli/bin/amp /usr/local/bin/amp
# The production reviewbot-v1 mode, loaded as a system plugin.
COPY docs/reviews/pinned-models.js /root/.config/amp/plugins/pinned-models.js
COPY --from=build /reviewbench-agent /usr/local/bin/reviewbench-agent
ENTRYPOINT ["/usr/local/bin/reviewbench-agent"]
