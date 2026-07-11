"""
modules/intel/gf_patterns.py

Phase 6 / Step 16 — Pattern Matching (gf-patterns).
Runs purely against already-collected URLs (final_urls.txt from Phase 4)
— no new network traffic — so this stays ungated.

Output: data/processed/interesting_params.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("intel.gf")

DEFAULT_PATTERNS = ["xss", "sqli", "redirect", "ssrf", "lfi", "idor"]


def _run_gf(binary: str, pattern: str, stdin_data: str, timeout: int = 60) -> str:
    try:
        proc = subprocess.run(
            [binary, pattern], input=stdin_data,
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout
    except FileNotFoundError:
        log.info("gf: not installed, skipping pattern matching")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"gf {pattern}: timed out")
        return ""


def gf_scan(cfg: Config, urls: Iterable[str], patterns: List[str] | None = None) -> dict:
    urls = list(urls)
    if not urls:
        log.warning("gf_scan called with empty URL list")
        return {}

    binary = cfg.tool_path("gf")
    patterns = patterns or DEFAULT_PATTERNS
    stdin_data = "\n".join(urls)

    results: dict[str, List[str]] = {}
    for pattern in patterns:
        out = _run_gf(binary, pattern, stdin_data)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if lines:
            results[pattern] = lines
        log.info(f"gf {pattern}: {len(lines)} matches")

    out_path = os.path.join(cfg.processed_dir, "interesting_params.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        for pattern, lines in results.items():
            f.write(f"# --- {pattern} ---\n")
            f.write("\n".join(lines) + "\n")

    total = sum(len(v) for v in results.values())
    log.info(f"gf pattern matching: {total} total matches across {len(patterns)} patterns -> {out_path}")
    return results
