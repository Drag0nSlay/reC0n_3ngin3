"""
modules/resolve/httpx_probe.py

Phase 2 / Step 5 — Alive Detection.
Runs httpx over resolved hosts to find which ones actually serve HTTP(S),
capturing status code, page title, and tech-stack fingerprinting.

This sends real HTTP requests to the target — gated on cfg.authorized.

Output: data/processed/live_domains.txt        (bare URLs, for chaining into crawl/scan)
        data/processed/live_domains_full.jsonl (one JSON object per host: url, status, title, tech, etc.)
"""

from __future__ import annotations
import json
import os
import subprocess
from typing import Set

from utils.dedupe import save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("resolve.httpx")


def probe_alive(cfg: Config, hosts: Set[str]) -> dict:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to send HTTP probes to "
            "the target. Set target.authorized: true once in scope."
        )
        return {"live_urls": set(), "records": []}

    if not hosts:
        log.warning("probe_alive called with empty host set")
        return {"live_urls": set(), "records": []}

    binary = cfg.tool_path("httpx") if hasattr(cfg, "tool_path") else "httpx"
    stdin_data = "\n".join(sorted(hosts))

    args = [
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-favicon",  # mmh3 hash of /favicon.ico — enables Shodan/Censys favicon pivoting
    ] + cfg.extra_args("httpx")

    try:
        proc = subprocess.run(
            [binary, *args], input=stdin_data,
            capture_output=True, text=True, timeout=900,
        )
        if proc.returncode != 0:
            log.warning(f"httpx exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        raw_out = proc.stdout
    except FileNotFoundError:
        log.info("httpx: not installed, skipping alive detection")
        raw_out = ""
    except subprocess.TimeoutExpired:
        log.warning("httpx: timed out after 15m")
        raw_out = ""

    records = []
    live_urls: Set[str] = set()
    for line in raw_out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(obj)
        url = obj.get("url")
        if url:
            live_urls.add(url)

    jsonl_path = os.path.join(cfg.processed_dir, "live_domains_full.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    urls_path = os.path.join(cfg.processed_dir, "live_domains.txt")
    save_set(urls_path, live_urls, )

    log.info(f"httpx: {len(live_urls)}/{len(hosts)} hosts alive -> {urls_path}")

    # Quick high-signal summary for the operator (interesting tech / high status codes)
    interesting = [r for r in records if r.get("status_code", 0) in (401, 403, 500) or r.get("tech")]
    if interesting:
        log.info(f"httpx: {len(interesting)} hosts flagged interesting (auth-walled / errors / fingerprinted tech)")

    return {"live_urls": live_urls, "records": records}
