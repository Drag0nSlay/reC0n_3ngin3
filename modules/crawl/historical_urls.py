"""
modules/crawl/historical_urls.py

Phase 4 / Step 8 — Historical URLs.
Both waybackurls and gau query third-party archive/index services
(web.archive.org, Common Crawl, AlienVault OTX, urlscan.io) — they don't
send any traffic to the target itself, so this stays ungated like
Phase 1's passive sources.

Output: data/raw/urls_raw.txt (deduped)
"""

from __future__ import annotations
import os
import subprocess
from typing import Set

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("crawl.historical")


def _run_cli(binary: str, args: list[str], stdin_data: str | None = None, timeout: int = 300) -> str:
    try:
        proc = subprocess.run(
            [binary, *args], input=stdin_data,
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            log.warning(f"{binary} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out after {timeout}s")
        return ""


def waybackurls_fetch(cfg: Config) -> Set[str]:
    binary = cfg.tool_path("waybackurls")
    out = _run_cli(binary, [cfg.domain], timeout=300)
    result = dedupe_lines(out.splitlines(), normalize=False)
    log.info(f"waybackurls: {len(result)} URLs")
    return result


def gau_fetch(cfg: Config) -> Set[str]:
    binary = cfg.tool_path("gau")
    out = _run_cli(binary, [cfg.domain], timeout=300)
    result = dedupe_lines(out.splitlines(), normalize=False)
    log.info(f"gau: {len(result)} URLs")
    return result


def collect_historical_urls(cfg: Config) -> Set[str]:
    """Runs both sources and merges (principle #2: dedupe at every stage)."""
    merged: Set[str] = set()
    merged |= waybackurls_fetch(cfg)
    merged |= gau_fetch(cfg)

    out_path = os.path.join(cfg.raw_dir, "urls_raw.txt")
    save_set(out_path, merged, )
    log.info(f"Historical URL collection: {len(merged)} unique URLs -> {out_path}")
    return merged
