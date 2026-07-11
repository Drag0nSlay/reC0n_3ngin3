"""
modules/intel/waf_detect.py

Phase 6 / Step 14 — WAF Detection.
wafw00f sends a handful of probe requests to fingerprint any WAF/CDN in
front of a host — real traffic to the target, so gated on cfg.authorized.

Output: data/processed/waf.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("intel.waf")


def wafw00f_scan(cfg: Config, urls: Iterable[str]) -> List[str]:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to send WAF-detection "
            "probes to the target. Set target.authorized: true once in scope."
        )
        return []

    urls = list(urls)
    if not urls:
        return []

    binary = cfg.tool_path("wafw00f")
    results: List[str] = []

    for url in urls:
        try:
            proc = subprocess.run(
                [binary, url, "-a"], capture_output=True, text=True, timeout=60,
            )
            out = proc.stdout.strip()
            if out:
                results.append(f"{url} | {out.splitlines()[-1]}")
        except FileNotFoundError:
            log.info("wafw00f: not installed, skipping")
            break
        except subprocess.TimeoutExpired:
            log.warning(f"wafw00f: timed out on {url}")
            continue

    out_path = os.path.join(cfg.processed_dir, "waf.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + ("\n" if results else ""))

    log.info(f"wafw00f: scanned {len(urls)} URLs, {len(results)} results -> {out_path}")
    return results
