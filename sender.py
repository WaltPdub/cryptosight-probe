"""HTTP sender — POSTs discovered assets to the CryptoSight ingest endpoint.

Retry policy: up to 3 attempts with exponential back-off (2 s, 4 s).
Any non-2xx final response is raised as an exception.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import requests

from assets import DiscoveredAsset, SnifferStats

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_INITIAL_BACKOFF = 2.0


def send(
    endpoint: str,
    api_key: str,
    probe_version: str,
    hostname: str,
    assets: list[DiscoveredAsset],
    *,
    sniffer_stats: Optional[SnifferStats] = None,
    ssl_verify: bool = True,
) -> dict:
    """POST assets to <endpoint>/probes/ingest and return the parsed response."""
    url = endpoint.rstrip("/") + "/probes/ingest"

    payload: dict = {
        "assets": [a.to_dict() for a in assets],
        "probeVersion": probe_version,
        "hostname": hostname,
    }
    if sniffer_stats is not None:
        payload["snifferStats"] = sniffer_stats.to_dict()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    last_err: Optional[Exception] = None
    backoff = _INITIAL_BACKOFF

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = requests.post(
                url, json=payload, headers=headers, timeout=30, verify=ssl_verify
            )
            if resp.ok:
                try:
                    return resp.json()
                except Exception:
                    return {}
            last_err = RuntimeError(f"server returned {resp.status_code}: {resp.text[:200]}")
        except requests.RequestException as e:
            last_err = e

        if attempt < _MAX_ATTEMPTS:
            logger.warning(
                "WARN: ingest attempt %d/%d failed: %s — retrying in %.0fs",
                attempt, _MAX_ATTEMPTS, last_err, backoff,
            )
            time.sleep(backoff)
            backoff *= 2

    raise RuntimeError(f"ingest failed after {_MAX_ATTEMPTS} attempts: {last_err}")
