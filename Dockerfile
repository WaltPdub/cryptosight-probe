# ── Stage 1: build ────────────────────────────────────────────────────────────
#
# The passive sniffer uses google/gopacket which requires CGO and libpcap.
# We build on golang:1.22-alpine with Alpine's libpcap-dev (musl-based).
#
# Note: distroless/static cannot load shared libraries and distroless/cc uses
# glibc — neither is compatible with Alpine's musl CGO build.  We use
# alpine:3.19 as the final stage instead; it has a comparable attack surface
# (non-root user, no interactive shell, minimal package set) and is fully
# compatible with musl-linked binaries.
FROM golang:1.22-alpine AS builder

# libpcap-dev : headers + shared library for gopacket/pcap (requires CGO).
# gcc + musl-dev : C toolchain required to compile CGO code.
# git            : go mod tidy needs it for VCS-based module fetches.
# ca-certificates: needed at runtime for outbound HTTPS to the API.
RUN apk add --no-cache git ca-certificates libpcap-dev gcc musl-dev

WORKDIR /build

# Copy full source so go mod tidy can inspect all imports.
COPY . .

# Resolve and download all modules (generates go.sum if absent).
# This keeps the Dockerfile self-contained — no local `go mod tidy` required.
RUN go mod tidy

# Produce a dynamically-linked Linux/amd64 binary (CGO required for libpcap).
# -s -w strips symbol table and DWARF to reduce binary size.
# -X main.version stamps the build-time version string.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build \
    -ldflags="-s -w -X main.version=docker" \
    -o /probe .

# ── Stage 2: minimal Alpine runtime ───────────────────────────────────────────
#
# alpine:3.19 with only libpcap and ca-certificates installed.
# The probe runs as a dedicated non-root user (probe:probe).
FROM alpine:3.19

RUN apk add --no-cache libpcap ca-certificates && \
    addgroup -S probe && \
    adduser  -S probe -G probe

# Compiled probe binary from the builder stage.
COPY --from=builder /probe /probe

# Config is supplied at runtime via a volume mount on /config/config.yaml.
# See docker-compose.yml for the volume definition.
VOLUME ["/config"]

USER probe:probe

ENTRYPOINT ["/probe"]
