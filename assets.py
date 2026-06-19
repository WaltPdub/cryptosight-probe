"""Shared data types for the CryptoSight probe.

The DiscoveredAsset shape mirrors the TypeScript interface in
artifacts/api-server/src/lib/sensors/types.ts so the server's
validate → dedupe → upsert pipeline accepts it without modification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class DiscoveredAsset:
    uid: str
    name: str
    type: str                                          # certificate | key | crypto_library
    algorithm: str
    key_size: Optional[int] = None
    self_signed: bool = False
    is_quantum_vulnerable: bool = False
    extended_key_usage: list[str] = field(default_factory=list)
    subject_alternative_names: list[str] = field(default_factory=list)
    host: Optional[str] = None
    file_path: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    status: Optional[str] = None
    labels: list[str] = field(default_factory=list)
    custom_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "uid": self.uid,
            "name": self.name,
            "type": self.type,
            "algorithm": self.algorithm,
            "isQuantumVulnerable": self.is_quantum_vulnerable,
        }
        if self.key_size is not None:
            d["keySize"] = self.key_size
        if self.self_signed:
            d["selfSigned"] = True
        if self.extended_key_usage:
            d["extendedKeyUsage"] = self.extended_key_usage
        if self.subject_alternative_names:
            d["subjectAlternativeNames"] = self.subject_alternative_names
        if self.host is not None:
            d["host"] = self.host
        if self.file_path is not None:
            d["filePath"] = self.file_path
        if self.subject is not None:
            d["subject"] = self.subject
        if self.issuer is not None:
            d["issuer"] = self.issuer
        if self.serial_number is not None:
            d["serialNumber"] = self.serial_number
        if self.fingerprint is not None:
            d["fingerprint"] = self.fingerprint
        if self.valid_from is not None:
            d["validFrom"] = _iso(self.valid_from)
        if self.valid_to is not None:
            d["validTo"] = _iso(self.valid_to)
        if self.status is not None:
            d["status"] = self.status
        if self.labels:
            d["labels"] = self.labels
        if self.custom_metadata:
            d["customMetadata"] = self.custom_metadata
        return d


@dataclass
class SnifferStats:
    packets_total: int = 0
    active_streams: int = 0
    cipher_suites: list[str] = field(default_factory=list)
    buffer_depth: int = 0
    capture_started: str = ""

    def to_dict(self) -> dict:
        return {
            "packetsTotal": self.packets_total,
            "activeStreams": self.active_streams,
            "cipherSuites": sorted(self.cipher_suites),
            "bufferDepth": self.buffer_depth,
            "captureStarted": self.capture_started,
        }


def is_quantum_vulnerable(algorithm: str) -> bool:
    """Mirror the server-side classify.ts logic."""
    return algorithm in ("RSA", "ECDSA", "DSA")


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
