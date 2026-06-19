"""Passive TLS traffic sniffer using Scapy.

Captures live TCP traffic with a BPF filter, parses TLS Certificate
handshake messages from the raw payloads, and periodically flushes
discovered assets to the CryptoSight ingest API.

Unlike the Go/gopacket version this implementation does NOT do full
TCP stream reassembly — it parses TLS records that arrive in a single
packet payload.  Certificates in fragmented TLS records are skipped.
This is a deliberate trade-off: simpler code, no CGO, still catches the
vast majority of TLS handshakes on modern networks where Certificate
messages usually fit in a single TCP segment.

Requires CAP_NET_ADMIN + CAP_NET_RAW (see docker-compose.yml).
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from assets import DiscoveredAsset, SnifferStats
from cert_utils import parse_der_cert
from probe_config import Config
import sender as sender_mod

logger = logging.getLogger(__name__)

# TLS content type for Handshake records.
_TLS_HANDSHAKE = 22
# TLS Handshake message type for Certificate.
_HS_CERTIFICATE = 11


def run(cfg: Config, probe_version: str, stop_event: threading.Event) -> None:
    """Block until stop_event is set, capturing and flushing TLS assets."""
    try:
        from scapy.all import sniff, TCP, IP, conf as scapy_conf  # type: ignore
        scapy_conf.verb = 0
    except ImportError:
        logger.error("scapy is not installed — passive sniffer cannot start")
        return

    iface = cfg.sniffer.interface or "eth0"
    bpf = cfg.sniffer.bpf_filter or "tcp port 443 or tcp port 8443"
    flush_secs = cfg.sniffer.flush_interval_seconds or 60
    max_buf = cfg.sniffer.max_buffer_assets or 500

    # Thread-safe asset buffer keyed by UID (last-write wins within a window).
    buf: dict[str, DiscoveredAsset] = {}
    buf_lock = threading.Lock()
    stats = SnifferStats(capture_started=datetime.now(timezone.utc).isoformat())
    stats_lock = threading.Lock()

    hostname = socket.gethostname()
    probe_name = cfg.probe.name

    def on_packet(pkt) -> None:
        if not pkt.haslayer("TCP"):
            return
        payload = bytes(pkt["TCP"].payload)
        if not payload:
            return

        with stats_lock:
            stats.packets_total += 1

        assets = _extract_certs_from_payload(payload, probe_name)
        if not assets:
            return

        with buf_lock:
            for a in assets:
                buf[a.uid] = a
            depth = len(buf)

        if depth >= max_buf:
            _flush(cfg, probe_version, hostname, buf, buf_lock, stats, stats_lock)

    def flush_loop() -> None:
        while not stop_event.is_set():
            stop_event.wait(flush_secs)
            _flush(cfg, probe_version, hostname, buf, buf_lock, stats, stats_lock)

    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    logger.info(
        "INFO: passive sniffer started on interface %r (BPF: %r, flush every %ds, max buffer %d)",
        iface, bpf, flush_secs, max_buf,
    )

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=on_packet,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except Exception as e:
        logger.error("Sniffer error: %s", e)
    finally:
        stop_event.set()
        flush_thread.join(timeout=10)
        _flush(cfg, probe_version, hostname, buf, buf_lock, stats, stats_lock)
        logger.info("INFO: passive sniffer stopped")


def _flush(
    cfg: Config,
    probe_version: str,
    hostname: str,
    buf: dict,
    buf_lock: threading.Lock,
    stats: SnifferStats,
    stats_lock: threading.Lock,
) -> None:
    with buf_lock:
        assets = list(buf.values())
        depth = len(assets)
        buf.clear()

    with stats_lock:
        snap = SnifferStats(
            packets_total=stats.packets_total,
            active_streams=0,
            cipher_suites=[],
            buffer_depth=depth,
            capture_started=stats.capture_started,
        )

    logger.info("INFO: sniffer flush — %d asset(s), %d packets total", len(assets), snap.packets_total)

    try:
        resp = sender_mod.send(
            cfg.probe.endpoint,
            cfg.probe.api_key,
            probe_version,
            hostname,
            assets,
            sniffer_stats=snap,
            ssl_verify=cfg.probe.ssl_verify,
        )
        logger.info(
            "INFO: sniffer ingest complete — accepted=%d rejected=%d",
            resp.get("accepted", 0), resp.get("rejected", 0),
        )
    except Exception as e:
        logger.warning("WARN: sniffer flush error: %s", e)


def _extract_certs_from_payload(payload: bytes, probe_name: str) -> list[DiscoveredAsset]:
    """Parse TLS records from a raw TCP payload and extract any Certificate messages."""
    assets = []
    pos = 0

    while pos + 5 <= len(payload):
        content_type = payload[pos]
        rec_len = struct.unpack_from("!H", payload, pos + 3)[0]

        # Sanity check: max TLS record body = 2^14 + 2048.
        if rec_len > 18432:
            break

        rec_end = pos + 5 + rec_len
        if rec_end > len(payload):
            break  # fragmented record — skip

        if content_type == _TLS_HANDSHAKE:
            fragment = payload[pos + 5: rec_end]
            assets.extend(_parse_handshake(fragment, probe_name))

        pos = rec_end

    return assets


def _parse_handshake(data: bytes, probe_name: str) -> list[DiscoveredAsset]:
    assets = []
    pos = 0

    while pos + 4 <= len(data):
        msg_type = data[pos]
        msg_len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
        pos += 4

        if pos + msg_len > len(data):
            break

        body = data[pos: pos + msg_len]
        pos += msg_len

        if msg_type == _HS_CERTIFICATE:
            assets.extend(_parse_certificate_message(body, probe_name))

    return assets


def _parse_certificate_message(body: bytes, probe_name: str) -> list[DiscoveredAsset]:
    """Decode a TLS Certificate handshake message (handles TLS 1.2 and 1.3)."""
    if len(body) < 3:
        return []

    pos = 0

    # TLS 1.3: certificate_request_context (1-byte length prefix).
    is_tls13 = False
    ctx_len = body[0]
    tls13_pos = 1 + ctx_len
    if tls13_pos + 3 <= len(body):
        tls13_list_len = (body[tls13_pos] << 16) | (body[tls13_pos + 1] << 8) | body[tls13_pos + 2]
        if tls13_pos + 3 + tls13_list_len <= len(body):
            is_tls13 = True
            pos = tls13_pos

    # TLS 1.2 / fallback: certificate_list starts at byte 0.
    if not is_tls13:
        pos = 0

    if pos + 3 > len(body):
        return []

    total_len = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
    pos += 3
    end = pos + total_len

    if end > len(body):
        return []

    assets = []

    while pos + 3 <= end:
        cert_len = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
        pos += 3

        if pos + cert_len > end:
            break

        der = body[pos: pos + cert_len]
        pos += cert_len

        # TLS 1.3 per-cert extensions.
        if is_tls13 and pos + 2 <= end:
            ext_len = struct.unpack_from("!H", body, pos)[0]
            pos += 2 + ext_len

        a = parse_der_cert(
            der,
            uid_prefix="capture:cert",
            probe_name=probe_name,
            labels=["network_capture"],
            custom_metadata={"source": "network_capture", "sourceType": "network"},
        )
        if a:
            assets.append(a)

    return assets
