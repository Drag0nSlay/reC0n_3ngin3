"""
modules/content/screenshots.py

Phase 7 / Step 19 — Screenshots.
EyeWitness visits each live URL and renders/screenshots the page — real
traffic to the target (a full page load, not just a HEAD request), so
gated on cfg.authorized.

Output: data/processed/screens/  (EyeWitness's own report directory)
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("content.screenshots")


def eyewitness_capture(cfg: Config, urls: Iterable[str], timeout: int = 1800) -> str | None:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to screenshot the "
            "target's live pages. Set target.authorized: true once in scope."
        )
        return None

    urls = list(urls)
    if not urls:
        log.warning("eyewitness_capture called with empty URL list")
        return None

    out_dir = os.path.join(cfg.processed_dir, "screens")
    os.makedirs(out_dir, exist_ok=True)

    urls_file = os.path.join(cfg.raw_dir, "eyewitness_input.txt")
    with open(urls_file, "w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")

    binary = cfg.tool_path("eyewitness") if hasattr(cfg, "tool_path") else "eyewitness"
    args = ["-f", urls_file, "-d", out_dir, "--no-prompt"] + cfg.extra_args("eyewitness")

    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            log.warning(f"EyeWitness exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    except FileNotFoundError:
        log.info("EyeWitness: not installed, skipping screenshots")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"EyeWitness: timed out after {timeout}s")
        return None

    log.info(f"EyeWitness: captured {len(urls)} URLs -> {out_dir}")
    return out_dir
