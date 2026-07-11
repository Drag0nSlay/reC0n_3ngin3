"""
modules/secrets/js_extract.py

Phase 5 / Step 10 — JS Extraction.
Pure filtering of already-collected URLs (Phase 4 output) — no new
network activity, so this stays ungated.

Output: data/processed/js_files.txt
"""

from __future__ import annotations
import os
from typing import Set

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("secrets.js_extract")


def extract_js_files(cfg: Config, final_urls: Set[str]) -> Set[str]:
    js_urls = {u for u in final_urls if u.split("?")[0].split("#")[0].lower().endswith(".js")}
    js_urls = dedupe_lines(js_urls, normalize=False)

    out_path = os.path.join(cfg.processed_dir, "js_files.txt")
    save_set(out_path, js_urls, )
    log.info(f"JS extraction: {len(js_urls)} .js URLs -> {out_path}")
    return js_urls
