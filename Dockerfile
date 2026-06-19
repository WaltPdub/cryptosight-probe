# ── CryptoSight On-Prem Probe ─────────────────────────────────────────────────
# Pure-Python implementation — no Go, no CGO, no compilation step.
# Scapy uses ctypes to bind to libpcap at runtime (passive sniffer mode only);
# no C headers are required at build time.
FROM python:3.12-slim

ARG PROBE_VERSION=dev

# libpcap is required at runtime when passiveSniffer: true.
# It is a small shared library (~200 kB) — safe to include unconditionally.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

# Stamp the version so logs show the image tag.
ENV PROBE_VERSION=${PROBE_VERSION}

VOLUME ["/config"]

ENTRYPOINT ["python", "/app/main.py"]
