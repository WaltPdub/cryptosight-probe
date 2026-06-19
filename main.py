#!/usr/bin/env python3
"""CryptoSight On-Prem Probe

Actively scans IP ranges for TLS endpoints, reads local certificate
stores, and optionally sniffs live network traffic for TLS handshake
data — then ships all findings to the CryptoSight ingest API.

Usage:
    python main.py [--config /path/to/config.yaml]

The default config path is /config/config.yaml inside the Docker image
(mounted via docker-compose volume), falling back to ./config.yaml.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time

import probe_config as config_mod
import scanner
import certstore
import sender as sender_mod
from assets import DiscoveredAsset
from probe_config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

VERSION = os.environ.get("PROBE_VERSION", "dev")


def main() -> None:
    parser = argparse.ArgumentParser(description="CryptoSight on-prem probe")
    parser.add_argument(
        "--config",
        default=config_mod.default_config_path(),
        help="path to config.yaml",
    )
    args = parser.parse_args()

    try:
        cfg = config_mod.load(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error("ERROR: loading config %r: %s", args.config, e)
        sys.exit(1)

    logger.info("INFO: CryptoSight probe %r starting (version=%s)", cfg.probe.name, VERSION)

    if not cfg.probe.ssl_verify:
        logger.warning(
            "WARN: SSL certificate verification is DISABLED (CRYPTOSIGHT_VERIFY_SSL=false). "
            "Only use this for development or self-signed certificate environments."
        )

    stop_event = threading.Event()

    def _shutdown(sig, _frame):
        logger.info("INFO: received signal %s — shutting down", signal.Signals(sig).name)
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ── Passive sniffer (background thread) ────────────────────────────────
    sniffer_thread: threading.Thread | None = None
    if cfg.mode.passive_sniffer:
        import sniffer as sniffer_mod
        sniffer_thread = threading.Thread(
            target=sniffer_mod.run,
            args=(cfg, VERSION, stop_event),
            daemon=True,
            name="sniffer",
        )
        sniffer_thread.start()

    # ── Startup heartbeat ───────────────────────────────────────────────────
    # Send an empty ingest immediately so the server marks this probe Online
    # even before the first scan cycle completes.
    _send_heartbeat(cfg)

    # ── Active scan + cert-store cycle ─────────────────────────────────────
    needs_cycle = (cfg.mode.active_scan and cfg.scan.networks) or cfg.cert_store.enabled

    if needs_cycle:
        if cfg.scan.schedule:
            # Scheduled mode: check cron expression every 30s.
            logger.info("INFO: scan cycle scheduled on %r — waiting for first tick", cfg.scan.schedule)
            _run_scheduled(cfg, stop_event)
        else:
            # One-shot mode.
            err = _run_cycle(cfg)
            if err:
                logger.error("ERROR: scan cycle failed: %s", err)
                if not cfg.mode.passive_sniffer:
                    sys.exit(1)

            if not cfg.mode.passive_sniffer:
                logger.info("INFO: probe stopped")
                return
    else:
        logger.warning(
            "WARN: no scan targets configured (scan.networks is empty and certStore.enabled is false). "
            "Add CIDR ranges under scan.networks in config.yaml to start discovering assets. "
            "The probe will keep sending heartbeats every 5 minutes to stay Online."
        )
        # Keep running so heartbeats continue — user can update config and restart.
        _heartbeat_loop(cfg, stop_event)

    # Block until SIGTERM/SIGINT.
    stop_event.wait()

    if sniffer_thread:
        sniffer_thread.join(timeout=15)

    logger.info("INFO: probe stopped")


def _send_heartbeat(cfg: Config) -> None:
    """POST an empty asset list so the server updates lastSeenAt."""
    hostname = socket.gethostname()
    try:
        sender_mod.send(
            cfg.probe.endpoint, cfg.probe.api_key, VERSION, hostname, [],
            ssl_verify=cfg.probe.ssl_verify,
        )
        logger.info("INFO: heartbeat sent — probe is Online in CryptoSight")
    except Exception as e:
        logger.warning("WARN: heartbeat failed: %s — check endpoint and apiKey in config.yaml", e)


def _heartbeat_loop(cfg: Config, stop_event: threading.Event, interval: int = 300) -> None:
    """Send a heartbeat every `interval` seconds until stop_event is set."""
    while not stop_event.wait(timeout=interval):
        _send_heartbeat(cfg)


def _run_cycle(cfg: Config) -> Exception | None:
    hostname = socket.gethostname()
    assets: list[DiscoveredAsset] = []

    if cfg.mode.active_scan and cfg.scan.networks:
        logger.info(
            "INFO: active TLS scan starting — %d network(s), ports %s, concurrency %d",
            len(cfg.scan.networks), cfg.scan.ports, cfg.scan.concurrency,
        )
        try:
            found = scanner.run(cfg)
            logger.info("INFO: active scan complete — %d TLS asset(s) found", len(found))
            assets.extend(found)
        except Exception as e:
            logger.warning("WARN: active scan error: %s", e)

    if cfg.cert_store.enabled:
        logger.info("INFO: cert store scan starting — %d path(s)", len(cfg.cert_store.paths))
        try:
            found = certstore.run(cfg)
            logger.info("INFO: cert store scan complete — %d asset(s) found", len(found))
            assets.extend(found)
        except Exception as e:
            logger.warning("WARN: cert store scan error: %s", e)

    logger.info("INFO: sending %d asset(s) to %s", len(assets), cfg.probe.endpoint)
    try:
        resp = sender_mod.send(
            cfg.probe.endpoint, cfg.probe.api_key, VERSION, hostname, assets,
            ssl_verify=cfg.probe.ssl_verify,
        )
        accepted = resp.get("accepted", 0)
        rejected = resp.get("rejected", 0)
        logger.info("INFO: ingest complete — accepted=%d rejected=%d", accepted, rejected)
        if rejected:
            logger.warning(
                "WARN: %d asset(s) rejected by server (check server logs for validation details)",
                rejected,
            )
        return None
    except Exception as e:
        return e


def _run_scheduled(cfg: Config, stop_event: threading.Event) -> None:
    """Poll a 5-field cron expression every 30 s and fire when it matches."""
    expr = cfg.scan.schedule.strip()
    last_run_minute = -1

    while not stop_event.is_set():
        now = time.localtime()
        current_minute = now.tm_hour * 60 + now.tm_min
        if current_minute != last_run_minute and _cron_matches(expr, now):
            last_run_minute = current_minute
            err = _run_cycle(cfg)
            if err:
                logger.warning("WARN: scheduled scan cycle failed: %s", err)
        stop_event.wait(timeout=30)

    logger.info("INFO: scan scheduler stopped")


def _cron_matches(expr: str, t: time.struct_time) -> bool:
    """Return True when the 5-field cron expression matches time t."""
    try:
        fields = expr.split()
        if len(fields) != 5:
            return False
        # (cron_field, current_value)
        pairs = [
            (fields[0], t.tm_min),
            (fields[1], t.tm_hour),
            (fields[2], t.tm_mday),
            (fields[3], t.tm_mon),
            (fields[4], t.tm_wday),
        ]
        for field, val in pairs:
            if field == "*":
                continue
            if "/" in field:
                step = int(field.split("/")[1])
                if val % step != 0:
                    return False
            elif "-" in field:
                lo, hi = map(int, field.split("-"))
                if not (lo <= val <= hi):
                    return False
            elif "," in field:
                if val not in {int(x) for x in field.split(",")}:
                    return False
            elif int(field) != val:
                return False
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
