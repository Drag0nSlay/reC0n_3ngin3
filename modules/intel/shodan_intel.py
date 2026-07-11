"""
modules/intel/shodan_intel.py

Phase 6 / Step 13 — Service Intelligence via Shodan.
Pure third-party API lookup — Shodan already scanned the internet, we're
just reading their index — so this is ungated like other passive
sources. Requires api_keys.shodan.

Output: data/processed/shodan.jsonl
"""

from __future__ import annotations
import json
import os
import time
from typing import Iterable, List

import requests

from utils.logger import get_logger
from core.config import Config

log = get_logger("intel.shodan")


def shodan_host_lookup(cfg: Config, ips: Iterable[str]) -> List[dict]:
    key = cfg.api_key("shodan")
    if not key:
        log.info("Shodan: no API key configured, skipping")
        return []

    ips = list(ips)
    results: List[dict] = []

    for ip in ips:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        try:
            r = requests.get(url, params={"key": key}, timeout=cfg.http_timeout)
            if r.status_code == 404:
                continue
            r.raise_for_status()
            results.append(r.json())
        except Exception as e:
            log.warning(f"Shodan lookup failed for {ip}: {e}")
        time.sleep(1)  # respect Shodan's rate limits on the free/dev tiers

    out_path = os.path.join(cfg.processed_dir, "shodan.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for rec in results:
            f.write(json.dumps(rec) + "\n")

    log.info(f"Shodan: {len(results)}/{len(ips)} hosts found -> {out_path}")
    return results
