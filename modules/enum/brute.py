"""
modules/enum/brute.py

Phase 1 / Step 3 — Brute Expansion.
Wraps shuffledns (mass DNS brute force + resolution) using a wordlist.
This is the first "semi-active" step (still just DNS queries, no target
traffic to HTTP/app layer) so it's gated behind cfg.authorized like
everything downstream of pure passive collection.
"""

from __future__ import annotations
import os
import subprocess
from typing import Set

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("enum.brute")

DEFAULT_WORDLIST_URL_HINT = (
    "Use a wordlist like SecLists' subdomains-top1million-5000.txt "
    "(https://github.com/danielmiessler/SecLists) — not bundled here."
)


def shuffledns_brute(cfg: Config, wordlist_path: str) -> Set[str]:
    if not cfg.authorized:
        log.error("target.authorized is False in settings.yaml — refusing to brute force. "
                   "Only enable this against assets you own or are contracted to test.")
        return set()

    if not os.path.exists(wordlist_path):
        log.warning(f"Wordlist not found at {wordlist_path}. {DEFAULT_WORDLIST_URL_HINT}")
        return set()

    binary = cfg.tool_path("shuffledns")
    resolvers = cfg.tool_path("resolvers_list")
    args = ["-d", cfg.domain, "-w", wordlist_path, "-silent"]
    if os.path.exists(resolvers):
        args += ["-r", resolvers]

    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0:
            log.warning(f"shuffledns exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        result = dedupe_lines(proc.stdout.splitlines())
    except FileNotFoundError:
        log.info("shuffledns: not installed, skipping brute expansion")
        result = set()
    except subprocess.TimeoutExpired:
        log.warning("shuffledns: timed out after 30m")
        result = set()

    path = os.path.join(cfg.raw_dir, "brute.txt")
    save_set(path, result)
    log.info(f"brute: {len(result)} domains -> {path}")
    return result


def merge_final(cfg: Config, *sets: Set[str]) -> Set[str]:
    """
    Step 3 final merge: `cat *.txt | sort -u > final_subdomains.txt`
    equivalent, done in-process for portability.
    """
    merged: Set[str] = set()
    for s in sets:
        merged |= s

    out_path = os.path.join(cfg.processed_dir, "final_subdomains.txt")
    save_set(out_path, merged)
    log.info(f"FINAL: {len(merged)} unique subdomains -> {out_path}")
    return merged
