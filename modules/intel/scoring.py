"""
modules/intel/scoring.py

Phase 10 — Intelligence Engine.
Turns raw phase outputs into prioritized, actionable target tiers
instead of leaving the operator to eyeball a dozen text files.

Scoring rules (deliberately simple and explainable — a scoring engine
you can't audit at a glance is worse than no scoring at all):

  HIGH:
    - "admin"/"login"/"portal"/"internal"/"vpn"/"staging" keyword in the
      host/URL, AND
    - a high-value open port (from modules.scan.services.HIGH_VALUE_PORTS
      or the httpx-detected host has an auth-walled response), AND
    - a login-page signal (title/body keyword, or 401/403 status)

  MEDIUM:
    - URL has query parameters, OR
    - a JS endpoint was discovered for that host (Phase 5 endpoints.txt)

  LOW:
    - everything else (static content, no params, no notable ports)

Output: data/processed/high_targets.txt
        data/processed/medium_targets.txt
        data/processed/low_targets.txt
"""

from __future__ import annotations
import os
import re
from typing import Dict, Iterable, List, Set

from utils.logger import get_logger
from core.config import Config
from modules.scan.services import HIGH_VALUE_PORTS

log = get_logger("intel.scoring")

ADMIN_KEYWORDS = re.compile(
    r"(admin|login|portal|internal|vpn|staging|dashboard|manage|console|cpanel)",
    re.IGNORECASE,
)
LOGIN_PAGE_KEYWORDS = re.compile(r"(log ?in|sign ?in|password|username|admin panel)", re.IGNORECASE)


def _host_of(url_or_host: str) -> str:
    h = url_or_host.split("://", 1)[-1]
    h = h.split("/", 1)[0]
    return h.split(":")[0]


def score_targets(
    cfg: Config,
    final_urls: Iterable[str],
    port_pairs: Iterable[str],
    httpx_records: List[dict],
    endpoints: Iterable[str],
) -> Dict[str, Set[str]]:
    final_urls = list(final_urls)
    port_pairs = list(port_pairs)
    endpoints = list(endpoints)

    high_value_ports_by_host: Dict[str, Set[int]] = {}
    for pair in port_pairs:
        if ":" not in pair:
            continue
        host, _, port = pair.rpartition(":")
        if port.isdigit():
            high_value_ports_by_host.setdefault(host, set()).add(int(port))

    httpx_by_host = {}
    for rec in httpx_records:
        host = rec.get("host") or _host_of(rec.get("url", ""))
        if host:
            httpx_by_host[host] = rec

    endpoint_hosts = {_host_of(e) for e in endpoints if e}

    high: Set[str] = set()
    medium: Set[str] = set()
    low: Set[str] = set()

    for url in final_urls:
        host = _host_of(url)
        rec = httpx_by_host.get(host, {})
        title = (rec.get("title") or "")
        status = rec.get("status_code")
        ports_here = high_value_ports_by_host.get(host, set())

        has_admin_keyword = bool(ADMIN_KEYWORDS.search(url))
        has_high_value_port = bool(ports_here & HIGH_VALUE_PORTS) or status in (401, 403)
        has_login_signal = bool(LOGIN_PAGE_KEYWORDS.search(title)) or status in (401, 403)

        has_params = "?" in url and "=" in url.split("?", 1)[-1]
        has_js_endpoint = host in endpoint_hosts

        if has_admin_keyword and has_high_value_port and has_login_signal:
            high.add(url)
        elif has_params or has_js_endpoint:
            medium.add(url)
        else:
            low.add(url)

    _write(cfg, "high_targets.txt", high)
    _write(cfg, "medium_targets.txt", medium)
    _write(cfg, "low_targets.txt", low)

    log.info(f"Scoring: HIGH={len(high)} MEDIUM={len(medium)} LOW={len(low)}")
    return {"high": high, "medium": medium, "low": low}


def _write(cfg: Config, filename: str, items: Set[str]) -> None:
    path = os.path.join(cfg.processed_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(items)) + ("\n" if items else ""))
    log.info(f"{filename}: {len(items)} -> {path}")
