"""
modules/enum/deep_dns.py

Phase 9 / Step 21 — Deep DNS.
Unlike Phase 1's amass -passive, this runs dnsrecon and `amass enum
-active`, which perform zone-transfer attempts, DNS brute-forcing, and
active record enumeration directly against the target's nameservers —
real, fairly aggressive traffic to the target's DNS infrastructure.
Gated on cfg.authorized.

Output: data/processed/dns_full.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import List

from utils.logger import get_logger
from core.config import Config
from modules.enum.passive_sources import _detect_amass_version, _diagnose_amass_error

log = get_logger("enum.deep_dns")


def _authorized_or_bail(cfg: Config) -> bool:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to run active DNS "
            "enumeration (zone transfers, DNS brute force) against the "
            "target's nameservers. Set target.authorized: true once in scope."
        )
        return False
    return True


def dnsrecon_scan(cfg: Config, timeout: int = 600) -> str:
    if not _authorized_or_bail(cfg):
        return ""

    binary = cfg.tool_path("dnsrecon") if hasattr(cfg, "tool_path") else "dnsrecon"
    args = ["-d", cfg.domain, "-a"] + cfg.extra_args("dnsrecon")  # -a: perform AXFR (zone transfer) attempts too

    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            log.warning(f"dnsrecon exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info("dnsrecon: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"dnsrecon: timed out after {timeout}s")
        return ""


def amass_active(cfg: Config, timeout: int = 1800) -> str:
    if not _authorized_or_bail(cfg):
        return ""

    binary = cfg.tool_path("amass") if hasattr(cfg, "tool_path") else "amass"
    version = _detect_amass_version(binary)
    args = ["enum", "-active", "-d", cfg.domain] + cfg.extra_args("amass")

    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            _diagnose_amass_error(proc.stderr, binary)
        return proc.stdout
    except FileNotFoundError:
        log.info("amass: not installed, skipping active enum")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"amass active: timed out after {timeout}s")
        return ""


def run_deep_dns_stage(cfg: Config) -> List[str]:
    lines: List[str] = []

    dnsrecon_out = dnsrecon_scan(cfg)
    if dnsrecon_out:
        lines.append("# === dnsrecon ===")
        lines.extend(l for l in dnsrecon_out.splitlines() if l.strip())

    amass_out = amass_active(cfg)
    if amass_out:
        lines.append("# === amass (active) ===")
        lines.extend(l for l in amass_out.splitlines() if l.strip())

    out_path = os.path.join(cfg.processed_dir, "dns_full.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    log.info(f"deep DNS stage: {len(lines)} output lines -> {out_path}")
    return lines
