# ── Stage 1: build ────────────────────────────────────────────────────────────
# Use Debian-based builder — gopacket's CGO pcap bindings rely on <pcap.h>
# being on the standard include path, which Debian's libpcap-dev satisfies
# cleanly.  Alpine puts headers under pcap/pcap.h and has historically caused
# silent CGO link failures with gopacket v1.1.19.
FROM golang:1.22-bookworm AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GIT_COMMIT=dev

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev gcc ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod ./

ENV GONOSUMDB=* GONOSUMCHECK=* GOFLAGS=-mod=mod
RUN go mod download

COPY . .

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
