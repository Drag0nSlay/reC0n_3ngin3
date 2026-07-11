"""
modules/enum/passive_sources.py

Phase 1 / Step 1 — Base Assets (passive-only, no packets sent to the target).
Each function is independent, fails soft (returns empty set + logs a
warning on error), and writes its own raw output file for auditability.

Sources implemented:
  - crt.sh                (certificate transparency, no key needed)
  - VirusTotal            (subdomains endpoint, needs api_keys.virustotal)
  - Chaos (ProjectDiscovery) (needs api_keys.chaos)
  - GitHub code search    (regex-grep for "*.domain" in public code, needs github_token)
  - subfinder / assetfinder / amass (passive mode) — CLI wrappers, optional binaries

All results are normalized + deduped via utils.dedupe before returning.
"""

from __future__ import annotations
import json
import os
import subprocess
import time
from typing import Set

import requests

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("enum.passive")


def _write_raw(cfg: Config, name: str, domains: Set[str]) -> None:
    path = os.path.join(cfg.raw_dir, f"{name}.txt")
    save_set(path, domains)
    log.info(f"{name}: {len(domains)} domains -> {path}")


# ---------------------------------------------------------------- crt.sh ----
def crtsh(cfg: Config) -> Set[str]:
    domain = cfg.domain
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=cfg.http_timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.warning(f"crt.sh failed: {e}")
        return set()

    names = []
    for entry in data:
        # name_value can contain multiple newline-separated SANs
        names.extend(entry.get("name_value", "").split("\n"))

    result = dedupe_lines(names)
    result = {d for d in result if d.endswith(domain)}
    _write_raw(cfg, "crtsh", result)
    return result


# ------------------------------------------------------------ VirusTotal ----
def virustotal(cfg: Config) -> Set[str]:
    key = cfg.api_key("virustotal")
    if not key:
        log.info("VirusTotal: no API key configured, skipping")
        return set()

    domain = cfg.domain
    out: Set[str] = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": key}

    try:
        while url:
            r = requests.get(url, headers=headers, timeout=cfg.http_timeout)
            r.raise_for_status()
            body = r.json()
            for item in body.get("data", []):
                sub_id = item.get("id")
                if sub_id:
                    out.add(sub_id)
            url = body.get("links", {}).get("next")
            time.sleep(1)  # respect VT rate limits
    except Exception as e:
        log.warning(f"VirusTotal failed: {e}")

    out = dedupe_lines(out)
    _write_raw(cfg, "virustotal", out)
    return out


# ----------------------------------------------------------------- Chaos ----
def chaos(cfg: Config) -> Set[str]:
    key = cfg.api_key("chaos")
    if not key:
        log.info("Chaos: no API key configured, skipping")
        return set()

    domain = cfg.domain
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    headers = {"Authorization": key}

    try:
        r = requests.get(url, headers=headers, timeout=cfg.http_timeout)
        r.raise_for_status()
        body = r.json()
        subs = body.get("subdomains", [])
        out = {f"{s}.{domain}" for s in subs}
    except Exception as e:
        log.warning(f"Chaos failed: {e}")
        return set()

    out = dedupe_lines(out)
    _write_raw(cfg, "chaos", out)
    return out


# -------------------------------------------------------- GitHub search ----
def github_subdomains(cfg: Config) -> Set[str]:
    """
    Greps public GitHub code search for literal subdomain mentions.
    Cheap, high-signal source for internal/staging hosts leaked in configs.
    """
    token = cfg.api_key("github_token")
    if not token:
        log.info("GitHub: no token configured, skipping")
        return set()

    domain = cfg.domain
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    query = f'"{domain}"'
    url = "https://api.github.com/search/code"

    out: Set[str] = set()
    try:
        r = requests.get(url, headers=headers, params={"q": query, "per_page": 50}, timeout=cfg.http_timeout)
        r.raise_for_status()
        body = r.json()
        # We only harvest matching text fragments the API gives us back;
        # a deeper pass would fetch raw file contents and regex them.
        for item in body.get("items", []):
            frag = item.get("text_matches", [])
            for m in frag:
                text = m.get("fragment", "")
                for token_ in text.replace('"', " ").replace("'", " ").split():
                    if token_.endswith(domain) and "." in token_:
                        out.add(token_.strip(".,;:()[]{}"))
    except Exception as e:
        log.warning(f"GitHub search failed: {e}")

    out = dedupe_lines(out)
    _write_raw(cfg, "github", out)
    return out


# ---------------------------------------------------------- CLI wrappers ----
def _run_cli(binary: str, args: list[str], timeout: int = 120) -> str:
    try:
        proc = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=timeout
        )
        if proc.returncode != 0:
            log.warning(f"{binary} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed / not on PATH, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out after {timeout}s")
        return ""


def subfinder(cfg: Config) -> Set[str]:
    binary = cfg.tool_path("subfinder")
    out = _run_cli(binary, ["-d", cfg.domain, "-silent", "-all"])
    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "subfinder", result)
    return result


def assetfinder(cfg: Config) -> Set[str]:
    binary = cfg.tool_path("assetfinder")
    out = _run_cli(binary, ["--subs-only", cfg.domain])
    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "assetfinder", result)
    return result


def amass_passive(cfg: Config) -> Set[str]:
    binary = cfg.tool_path("amass")
    out = _run_cli(binary, ["enum", "-passive", "-d", cfg.domain], timeout=300)
    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "amass", result)
    return result


# --------------------------------------------------------------- runner ----
ALL_SOURCES = {
    "crtsh": crtsh,
    "virustotal": virustotal,
    "chaos": chaos,
    "github": github_subdomains,
    "subfinder": subfinder,
    "assetfinder": assetfinder,
    "amass": amass_passive,
}


def run_all_passive(cfg: Config, max_workers: int | None = None) -> Set[str]:
    """Fan out all passive sources concurrently (principle #4), merge + dedupe."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    workers = max_workers or cfg.max_workers
    merged: Set[str] = set()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn, cfg): name for name, fn in ALL_SOURCES.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                merged |= fut.result()
            except Exception as e:
                log.warning(f"Source {name} raised: {e}")

    out_path = os.path.join(cfg.raw_dir, "all_subdomains_raw.txt")
    save_set(out_path, merged)
    log.info(f"Passive enumeration total: {len(merged)} unique domains -> {out_path}")
    return merged
