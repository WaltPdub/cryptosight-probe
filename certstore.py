"""Local certificate store reader.

Walks configured directories and parses every certificate file it
finds.  Supported formats: PEM (.pem/.crt/.cer), DER (.der),
PKCS#12 (.p12/.pfx).  JKS is attempted via keytool if available.
Files that cannot be parsed are skipped with a warning.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

from assets import DiscoveredAsset
from cert_utils import parse_der_cert
from probe_config import Config

logger = logging.getLogger(__name__)

_PKCS12_PASSWORDS = [b"", b"changeit", b"password", b"secret"]


def run(cfg: Config) -> list[DiscoveredAsset]:
    seen: set[str] = set()
    assets: list[DiscoveredAsset] = []

    for directory in cfg.cert_store.paths:
        p = Path(directory)
        if not p.exists():
            logger.warning("WARN: cert store path not found: %s", directory)
            continue
        for path in p.rglob("*"):
            if not path.is_file():
                continue
            for a in _parse_file(path, cfg.probe.name):
                if a.fingerprint and a.fingerprint not in seen:
                    seen.add(a.fingerprint)
                    assets.append(a)

    return assets


def _parse_file(path: Path, probe_name: str) -> list[DiscoveredAsset]:
    ext = path.suffix.lower()
    if ext in (".pem", ".crt", ".cer"):
        return _parse_pem(path, probe_name)
    if ext == ".der":
        return _parse_der(path, probe_name)
    if ext in (".p12", ".pfx"):
        return _parse_pkcs12(path, probe_name)
    if ext == ".jks":
        return _parse_jks(path, probe_name)
    return []


def _make_asset(der: bytes, path: Path, probe_name: str) -> Optional[DiscoveredAsset]:
    return parse_der_cert(
        der,
        uid_prefix="certstore",
        probe_name=probe_name,
        file_path=str(path.resolve()),
        labels=["cert_store"],
        custom_metadata={"source": "cert_store"},
    )


def _parse_pem(path: Path, probe_name: str) -> list[DiscoveredAsset]:
    try:
        data = path.read_bytes()
    except OSError as e:
        logger.warning("WARN: cannot read %s: %s", path, e)
        return []

    assets = []
    rest = data
    begin_marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"

    while True:
        begin = rest.find(begin_marker)
        if begin == -1:
            break
        end = rest.find(end_marker, begin)
        if end == -1:
            break
        pem_block = rest[begin: end + len(end_marker)]
        rest = rest[end + len(end_marker):]
        try:
            cert = x509.load_pem_x509_certificate(pem_block)
            der = cert.public_bytes(Encoding.DER)
            a = _make_asset(der, path, probe_name)
            if a:
                assets.append(a)
        except Exception as e:
            logger.warning("WARN: cannot parse PEM cert in %s: %s", path, e)

    return assets


def _parse_der(path: Path, probe_name: str) -> list[DiscoveredAsset]:
    try:
        der = path.read_bytes()
    except OSError as e:
        logger.warning("WARN: cannot read %s: %s", path, e)
        return []
    a = _make_asset(der, path, probe_name)
    return [a] if a else []


def _parse_pkcs12(path: Path, probe_name: str) -> list[DiscoveredAsset]:
    try:
        data = path.read_bytes()
    except OSError as e:
        logger.warning("WARN: cannot read %s: %s", path, e)
        return []

    for pwd in _PKCS12_PASSWORDS:
        try:
            p12 = pkcs12.load_pkcs12(data, pwd)
        except Exception:
            continue

        certs = []
        if p12.cert and p12.cert.certificate:
            certs.append(p12.cert.certificate)
        for ac in p12.additional_certs or []:
            if ac.certificate:
                certs.append(ac.certificate)

        assets = []
        for cert in certs:
            der = cert.public_bytes(Encoding.DER)
            a = _make_asset(der, path, probe_name)
            if a:
                assets.append(a)
        if assets:
            return assets

    logger.warning("WARN: could not decode PKCS#12 %s — unknown password or format", path)
    return []


def _parse_jks(path: Path, probe_name: str) -> list[DiscoveredAsset]:
    try:
        result = subprocess.run(["which", "keytool"], capture_output=True)
        if result.returncode != 0:
            logger.info("INFO: skipping JKS %s — keytool not in PATH", path)
            return []
    except Exception:
        return []

    begin_marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"

    for store_pass in ("", "changeit"):
        try:
            result = subprocess.run(
                ["keytool", "-list", "-rfc", "-keystore", str(path),
                 "-storepass", store_pass, "-noprompt"],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                continue
            data = result.stdout
            assets = []
            rest = data
            while True:
                begin = rest.find(begin_marker)
                if begin == -1:
                    break
                end = rest.find(end_marker, begin)
                if end == -1:
                    break
                pem_block = rest[begin: end + len(end_marker)]
                rest = rest[end + len(end_marker):]
                try:
                    cert = x509.load_pem_x509_certificate(pem_block)
                    der = cert.public_bytes(Encoding.DER)
                    a = _make_asset(der, path, probe_name)
                    if a:
                        assets.append(a)
                except Exception:
                    pass
            if assets:
                return assets
        except Exception as e:
            logger.debug("keytool error on %s: %s", path, e)

    logger.warning("WARN: could not read JKS %s — check keytool or store password", path)
    return []
