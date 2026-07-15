"""
modules/crawl/live_crawl.py

Phase 4 / Step 9 — Live Crawling, plus the final URL merge.
katana actually visits pages on the live hosts to discover linked URLs,
forms, and JS references — real traffic to the target — so it's gated
on cfg.authorized.

Output: data/processed/urls_live.txt
        data/processed/final_urls.txt  (historical + live, deduped)
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, Set

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("crawl.live")


def katana_crawl(cfg: Config, live_urls: Iterable[str], depth: int = 3) -> Set[str]:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to crawl the target live. "
            "Set target.authorized: true once in scope."
        )
        return set()

    live_urls = list(live_urls)
    if not live_urls:
        log.warning("katana_crawl called with empty URL list")
        return set()

    binary = cfg.tool_path("katana")
    args = ["-silent", "-depth", str(depth), "-jc"] + cfg.extra_args("katana")  # -jc: also parse JS files for endpoints
    out = _run_cli(binary, args, stdin_data="\n".join(live_urls), timeout=1200)

    result = dedupe_lines(out.splitlines(), normalize=False)
    out_path = os.path.join(cfg.processed_dir, "urls_live.txt")
    save_set(out_path, result, )
    log.info(f"katana: {len(result)} URLs discovered -> {out_path}")
    return result


def _run_cli(binary: str, args: list[str], stdin_data: str | None = None, timeout: int = 600) -> str:
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


def merge_final_urls(cfg: Config, historical: Set[str], live: Set[str]) -> Set[str]:
    merged = dedupe_lines(historical | live, normalize=False)
    out_path = os.path.join(cfg.processed_dir, "final_urls.txt")
    save_set(out_path, merged, )
    log.info(f"FINAL URLs: {len(merged)} unique -> {out_path}")
    return merged
