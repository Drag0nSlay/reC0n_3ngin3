"""
modules/scan/nuclei_scan.py

Phase 6 / Step 15 — Template Scanning (safe templates only).
Sends real requests to the target, so gated on cfg.authorized. To honor
the "safe templates only" requirement, this hard-restricts nuclei to:
  - severity: info,low (from settings.yaml scan.nuclei_severity)
  - excludes intrusive/dos/fuzz tags (scan.nuclei_exclude_tags)
There is no parameter to widen this beyond what's in settings.yaml from
inside this module — if you need broader coverage (medium/high/critical
severity templates, exploit-style checks), that's a deliberate decision
you make explicitly in config, not a default this pipeline reaches for.

Output: data/processed/nuclei.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("scan.nuclei")


def nuclei_safe_scan(cfg: Config, urls: Iterable[str]) -> List[str]:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to run nuclei against "
            "the target. Set target.authorized: true once in scope."
        )
        return []

    urls = list(urls)
    if not urls:
        log.warning("nuclei_safe_scan called with empty URL list")
        return []

    binary = cfg.tool_path("nuclei")
    args = [
        "-silent",
        "-severity", cfg.nuclei_severity,
        "-exclude-tags", cfg.nuclei_exclude_tags,
    ]

    try:
        proc = subprocess.run(
            [binary, *args], input="\n".join(urls),
            capture_output=True, text=True, timeout=1800,
        )
        if proc.returncode != 0:
            log.warning(f"nuclei exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        out = proc.stdout
    except FileNotFoundError:
        log.info("nuclei: not installed, skipping")
        out = ""
    except subprocess.TimeoutExpired:
        log.warning("nuclei: timed out after 30m")
        out = ""

    results = [l.strip() for l in out.splitlines() if l.strip()]

    out_path = os.path.join(cfg.processed_dir, "nuclei.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + ("\n" if results else ""))

    log.info(
        f"nuclei (severity={cfg.nuclei_severity}, excluded={cfg.nuclei_exclude_tags}): "
        f"{len(results)} findings -> {out_path}"
    )
    return results
