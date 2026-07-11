"""
modules/enum/asn_ip.py

Phase 1 / Step 2 — ASN + IP Mapping.

  - ARIN WHOIS (RDAP, no key needed)
  - bgp.he.net scrape (best-effort HTML parse; He.net has no public API)
  - asnmap / mapcidr CLI wrappers (ProjectDiscovery tools)

Outputs: asn.txt, ip_ranges.txt, cidr.txt, ips.txt under data/raw/
"""

from __future__ import annotations
import ipaddress
import os
import re
import subprocess
from typing import Set

import requests

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("enum.asn_ip")


def _write_raw(cfg: Config, name: str, items: Set[str]) -> None:
    path = os.path.join(cfg.raw_dir, f"{name}.txt")
    save_set(path, items, )
    log.info(f"{name}: {len(items)} entries -> {path}")


# --------------------------------------------------------- ARIN / RDAP ----
def arin_whois(cfg: Config, org_name: str | None = None) -> Set[str]:
    """
    Query ARIN's RDAP search for organization -> networks.
    org_name defaults to the domain's registrable name (best-effort).
    """
    org_name = org_name or cfg.domain.split(".")[0]
    url = f"https://rdap.arin.net/registry/entities?fn={org_name}"
    out: Set[str] = set()
    try:
        r = requests.get(url, timeout=cfg.http_timeout, headers={"Accept": "application/rdap+json"})
        r.raise_for_status()
        body = r.json()
        for entity in body.get("entitySearchResults", []):
            handle = entity.get("handle")
            if handle:
                out.add(handle)
    except Exception as e:
        log.warning(f"ARIN RDAP lookup failed: {e}")
    _write_raw(cfg, "arin_handles", out)
    return out


# ------------------------------------------------------------ bgp.he.net --
def bgp_he_net(cfg: Config, asn_or_org: str) -> Set[str]:
    """
    Best-effort scrape of bgp.he.net's AS prefix listing page.
    NOTE: HTML structure changes over time; treat this as a starting point,
    not a guaranteed parser. Falls back gracefully if the page shape changed.
    """
    url = f"https://bgp.he.net/{asn_or_org}"
    out: Set[str] = set()
    try:
        r = requests.get(
            url, timeout=cfg.http_timeout,
            headers={"User-Agent": "Mozilla/5.0 (recon-engine)"}
        )
        r.raise_for_status()
        # crude CIDR extraction — works regardless of exact HTML structure
        cidrs = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", r.text)
        out |= set(cidrs)
    except Exception as e:
        log.warning(f"bgp.he.net scrape failed for {asn_or_org}: {e}")
    return out


# --------------------------------------------------------------- asnmap ---
def _run_cli(binary: str, args: list[str], timeout: int = 60) -> str:
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            log.warning(f"{binary} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out")
        return ""


def asnmap_lookup(cfg: Config) -> Set[str]:
    """Resolve domain -> ASN -> CIDR ranges via asnmap CLI."""
    binary = cfg.tool_path("asnmap")
    out = _run_cli(binary, ["-d", cfg.domain, "-silent"])
    result = dedupe_lines(out.splitlines(), normalize=False)
    _write_raw(cfg, "asn", result)
    return result


def mapcidr_expand(cfg: Config, cidrs: Set[str]) -> Set[str]:
    """Expand CIDR ranges to individual IPs via mapcidr CLI (piped input)."""
    binary = cfg.tool_path("mapcidr")
    if not cidrs:
        return set()
    try:
        proc = subprocess.run(
            [binary, "-silent"],
            input="\n".join(sorted(cidrs)),
            capture_output=True, text=True, timeout=120,
        )
        result = dedupe_lines(proc.stdout.splitlines(), normalize=False)
    except FileNotFoundError:
        log.info("mapcidr: not installed, falling back to python ipaddress expansion")
        result = set()
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if net.num_addresses <= 65536:  # safety cap, avoid exploding /8s etc
                    result |= {str(ip) for ip in net.hosts()}
                else:
                    log.warning(f"Skipping huge range {cidr} ({net.num_addresses} addrs) — expand manually if needed")
            except ValueError as e:
                log.warning(f"Invalid CIDR {cidr}: {e}")
    except subprocess.TimeoutExpired:
        log.warning("mapcidr: timed out")
        result = set()

    _write_raw(cfg, "ips", result)
    return result


def run_asn_ip_stage(cfg: Config) -> dict:
    """Orchestrate step 2 end to end, returns dict of all artifacts."""
    asn = asnmap_lookup(cfg)
    cidrs = dedupe_lines(asn, normalize=False)  # asnmap output is often already CIDR-ish
    # Also try org-name based ARIN + he.net scrape as a secondary/manual-supplement path
    handles = arin_whois(cfg)
    for handle in handles:
        cidrs |= bgp_he_net(cfg, handle)

    _write_raw(cfg, "cidr", cidrs)
    ips = mapcidr_expand(cfg, cidrs)

    return {"asn": asn, "cidr": cidrs, "ips": ips}
