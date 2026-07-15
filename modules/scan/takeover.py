"""
modules/scan/takeover.py

Phase 6 / Step 17 — Subdomain Takeover.
subzy sends DNS lookups + HTTP requests to each candidate subdomain to
check for dangling CNAME / takeover fingerprints — real traffic to the
target's DNS/HTTP surface, so gated on cfg.authorized.

Output: data/processed/takeover.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("scan.takeover")


def subzy_scan(cfg: Config, subdomains: Iterable[str]) -> List[str]:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to run subdomain "
            "takeover checks against the target. Set target.authorized: "
            "true once in scope."
        )
        return []

    subdomains = list(subdomains)
    if not subdomains:
        log.warning("subzy_scan called with empty subdomain list")
        return []

    binary = cfg.tool_path("subzy")
    stdin_data = "\n".join(subdomains)

    try:
        proc = subprocess.run(
            [binary, "run", "--targets", "-", "--hide_fails"] + cfg.extra_args("subzy"),
            input=stdin_data, capture_output=True, text=True, timeout=900,
        )
        if proc.returncode != 0:
            log.warning(f"subzy exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        out = proc.stdout
    except FileNotFoundError:
        log.info("subzy: not installed, skipping takeover checks")
        out = ""
    except subprocess.TimeoutExpired:
        log.warning("subzy: timed out after 15m")
        out = ""

    results = [l.strip() for l in out.splitlines() if l.strip()]

    out_path = os.path.join(cfg.processed_dir, "takeover.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + ("\n" if results else ""))

    log.info(f"subzy: {len(results)} flagged results across {len(subdomains)} subdomains -> {out_path}")
    return results
