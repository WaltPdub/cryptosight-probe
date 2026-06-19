"""Active TLS scanner.

Dials every host:port in the configured CIDR ranges, performs a TLS
handshake (InsecureSkipVerify — we want the cert even when it's
untrusted), and converts each certificate in the peer chain to a
DiscoveredAsset.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from assets import DiscoveredAsset
from cert_utils import parse_der_cert
from probe_config import Config

logger = logging.getLogger(__name__)


def run(cfg: Config) -> list[DiscoveredAsset]:
    timeout = float(cfg.scan.timeout_seconds)
    probe_name = cfg.probe.name

    targets: list[tuple[str, int]] = []
    for cidr in cfg.scan.networks:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            for ip in net.hosts():
                for port in cfg.scan.ports:
                    targets.append((str(ip), port))
        except ValueError as e:
            logger.warning("Skipping invalid CIDR %r: %s", cidr, e)

    seen: set[str] = set()
    assets: list[DiscoveredAsset] = []

    def _scan(host: str, port: int) -> list[DiscoveredAsset]:
        return _scan_target(host, port, probe_name, timeout)

    with ThreadPoolExecutor(max_workers=cfg.scan.concurrency) as pool:
        futures = {pool.submit(_scan, h, p): (h, p) for h, p in targets}
        for future in as_completed(futures):
            try:
                for a in future.result():
                    if a.uid not in seen:
                        seen.add(a.uid)
                        assets.append(a)
            except Exception as e:
                h, p = futures[future]
                logger.debug("Unexpected error scanning %s:%d: %s", h, p, e)

    return assets


def _scan_target(host: str, port: int, probe_name: str, timeout: float) -> list[DiscoveredAsset]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else "unknown"
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return []

    if not der:
        return []

    a = parse_der_cert(
        der,
        uid_prefix="tls",
        probe_name=probe_name,
        host=host,
        labels=["tls", f"port:{port}"],
        custom_metadata={"port": port, "negotiatedCipher": cipher_name},
    )
    return [a] if a else []
