"""YAML configuration loader for the CryptoSight probe."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml


@dataclass
class ProbeConfig:
    name: str
    api_key: str
    endpoint: str


@dataclass
class ScanConfig:
    networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=lambda: [443, 8443, 636, 5671, 8080, 9200, 3269])
    concurrency: int = 50
    timeout_seconds: int = 5
    schedule: str = ""


@dataclass
class CertStoreConfig:
    enabled: bool = False
    paths: list[str] = field(default_factory=list)


@dataclass
class ModeConfig:
    active_scan: bool = True
    passive_sniffer: bool = False


@dataclass
class SnifferConfig:
    interface: str = "eth0"
    bpf_filter: str = "tcp port 443 or tcp port 8443"
    flush_interval_seconds: int = 60
    max_buffer_assets: int = 500


@dataclass
class Config:
    probe: ProbeConfig
    scan: ScanConfig = field(default_factory=ScanConfig)
    cert_store: CertStoreConfig = field(default_factory=CertStoreConfig)
    mode: ModeConfig = field(default_factory=ModeConfig)
    sniffer: SnifferConfig = field(default_factory=SnifferConfig)


def load(path: str) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    p = raw.get("probe", {})
    probe = ProbeConfig(
        name=p.get("name", ""),
        api_key=p.get("apiKey", ""),
        endpoint=p.get("endpoint", ""),
    )

    s = raw.get("scan", {})
    scan = ScanConfig(
        networks=s.get("networks") or [],
        ports=s.get("ports") or [443, 8443, 636, 5671, 8080, 9200, 3269],
        concurrency=s.get("concurrency") or 50,
        timeout_seconds=s.get("timeoutSeconds") or 5,
        schedule=s.get("schedule") or "",
    )

    cs = raw.get("certStore", {})
    cert_store = CertStoreConfig(
        enabled=bool(cs.get("enabled", False)),
        paths=cs.get("paths") or [],
    )

    m = raw.get("mode", {})
    mode = ModeConfig(
        active_scan=bool(m.get("activeScan", True)),
        passive_sniffer=bool(m.get("passiveSniffer", False)),
    )

    sn = raw.get("sniffer", {})
    sniffer = SnifferConfig(
        interface=sn.get("interface") or "eth0",
        bpf_filter=sn.get("bpfFilter") or "tcp port 443 or tcp port 8443",
        flush_interval_seconds=sn.get("flushIntervalSeconds") or 60,
        max_buffer_assets=sn.get("maxBufferAssets") or 500,
    )

    # Validation
    if not probe.name:
        raise ValueError("probe.name is required")
    if not probe.api_key:
        raise ValueError("probe.apiKey is required")
    if not probe.endpoint:
        raise ValueError("probe.endpoint is required")
    if not scan.networks and not cert_store.enabled and not mode.passive_sniffer:
        raise ValueError(
            "configure at least one discovery method: "
            "scan.networks, certStore.enabled=true, or mode.passiveSniffer=true"
        )
    if mode.passive_sniffer and not sniffer.interface:
        raise ValueError(
            'sniffer.interface is required when mode.passiveSniffer=true (e.g. "eth0" or "any")'
        )

    return Config(probe=probe, scan=scan, cert_store=cert_store, mode=mode, sniffer=sniffer)


def default_config_path() -> str:
    if os.path.exists("/config/config.yaml"):
        return "/config/config.yaml"
    return "config.yaml"
