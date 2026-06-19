# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GIT_COMMIT=dev

# libpcap-dev + gcc + musl-dev: required for CGO / gopacket pcap bindings
# git: required for go mod download VCS fetches
RUN apk add --no-cache ca-certificates libpcap-dev gcc musl-dev git

WORKDIR /build

# Copy module manifest first for better layer caching.
COPY go.mod ./

# Download all dependencies.  GONOSUMDB/GONOSUMCHECK skip the checksum
# database so the build is self-contained with no HTTPS dependency on
# sum.golang.org.  -mod=mod lets the go tool update go.sum at build time.
ENV GONOSUMDB=* GONOSUMCHECK=* GOFLAGS=-mod=mod
RUN go mod download

COPY . .

# -s -w strips debug info; -X stamps the git SHA into main.version.
RUN CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X main.version=${GIT_COMMIT}" \
    -o /probe .

# ── Stage 2: minimal Alpine runtime ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache libpcap ca-certificates && \
    addgroup -S probe && \
    adduser  -S probe -G probe

COPY --from=builder /probe /probe

VOLUME ["/config"]

USER probe:probe

ENTRYPOINT ["/probe"]
