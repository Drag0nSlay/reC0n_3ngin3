"""
modules/content/dir_bruteforce.py

Phase 7 / Step 18 — Directory Bruteforce.
ffuf/dirsearch throw hundreds-to-thousands of requests per host looking
for hidden paths — by far the noisiest, most request-heavy step so far.
Gated on cfg.authorized, AND deliberately restricted to a caller-supplied
"high priority" host list rather than every live host discovered — the
spec says "only on HIGH priority hosts" and this module enforces that by
requiring you pass that curated list explicitly (reuse
modules.scan.services.select_high_value_hosts or your own triage).

Output: data/processed/dirs.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

from utils.logger import get_logger
from core.config import Config

log = get_logger("content.dir_bruteforce")

DEFAULT_WORDLIST_HINT = (
    "Use a wordlist like SecLists' raft-medium-directories.txt "
    "(https://github.com/danielmiessler/SecLists) — not bundled here."
)


def _authorized_or_bail(cfg: Config) -> bool:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to directory-bruteforce "
            "the target. Set target.authorized: true once in scope."
        )
        return False
    return True


def ffuf_scan(cfg: Config, high_priority_urls: Iterable[str], wordlist_path: str,
              extensions: str = "", rate: int = 100, timeout_per_host: int = 600) -> List[str]:
    if not _authorized_or_bail(cfg):
        return []

    if not os.path.exists(wordlist_path):
        log.warning(f"Wordlist not found at {wordlist_path}. {DEFAULT_WORDLIST_HINT}")
        return []

    urls = list(high_priority_urls)
    if not urls:
        log.warning("ffuf_scan called with empty high-priority URL list — "
                     "this step should only ever run against a curated subset")
        return []

    binary = cfg.tool_path("ffuf") if hasattr(cfg, "tool_path") else "ffuf"
    results: List[str] = []

    for url in urls:
        target = url.rstrip("/") + "/FUZZ"
        args = ["-u", target, "-w", wordlist_path, "-rate", str(rate), "-s"] + cfg.extra_args("ffuf")  # -s: silent, only matches
        if extensions:
            args += ["-e", extensions]
        try:
            proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout_per_host)
            if proc.returncode not in (0, 1):
                log.warning(f"ffuf exited {proc.returncode} for {url}: {proc.stderr.strip()[:300]}")
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    results.append(f"{url} | {line}")
        except FileNotFoundError:
            log.info("ffuf: not installed, skipping")
            break
        except subprocess.TimeoutExpired:
            log.warning(f"ffuf: timed out on {url} after {timeout_per_host}s")
            continue

    _write_output(cfg, results)
    return results


def dirsearch_scan(cfg: Config, high_priority_urls: Iterable[str], extensions: str = "php,html,js,json",
                    timeout_per_host: int = 600) -> List[str]:
    if not _authorized_or_bail(cfg):
        return []

    urls = list(high_priority_urls)
    if not urls:
        log.warning("dirsearch_scan called with empty high-priority URL list")
        return []

    binary = cfg.tool_path("dirsearch") if hasattr(cfg, "tool_path") else "dirsearch"
    results: List[str] = []

    for url in urls:
        args = ["-u", url, "-e", extensions, "--format", "plain", "-q"] + cfg.extra_args("dirsearch")
        try:
            proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout_per_host)
            if proc.returncode not in (0, 1):
                log.warning(f"dirsearch exited {proc.returncode} for {url}: {proc.stderr.strip()[:300]}")
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    results.append(f"{url} | {line}")
        except FileNotFoundError:
            log.info("dirsearch: not installed, skipping")
            break
        except subprocess.TimeoutExpired:
            log.warning(f"dirsearch: timed out on {url} after {timeout_per_host}s")
            continue

    _write_output(cfg, results)
    return results


def _write_output(cfg: Config, results: List[str]) -> None:
    out_path = os.path.join(cfg.processed_dir, "dirs.txt")
    existing = []
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as f:
            existing = [l.strip() for l in f if l.strip()]
    merged = sorted(set(existing) | set(results))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(merged) + ("\n" if merged else ""))
    log.info(f"dir bruteforce: {len(results)} new hits, {len(merged)} total -> {out_path}")


def run_content_discovery_stage(cfg: Config, high_priority_urls: Iterable[str],
                                 wordlist_path: str | None = None) -> List[str]:
    """Runs ffuf if a wordlist is given, then dirsearch as a second pass (different engine, different hits)."""
    results: List[str] = []
    if wordlist_path:
        results.extend(ffuf_scan(cfg, high_priority_urls, wordlist_path))
    results.extend(dirsearch_scan(cfg, high_priority_urls))
    return results
