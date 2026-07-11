"""
modules/scan/ports.py

Phase 3 / Step 6 — Port Scanning Strategy (fast -> deep).

  1. naabu     — top-N ports, very fast, good default sweep across all hosts
  2. rustscan  — fast full-range confirm on hosts naabu found interesting
  3. masscan   — only invoked for large CIDR ranges (not single hosts),
                 and only if explicitly requested — it's the loudest/
                 riskiest tool of the three and easy to misconfigure into
                 an accidental internet-wide scan, so it never runs
                 implicitly.

Every step here sends packets directly at target infrastructure, so the
whole module is gated on cfg.authorized.

Output: data/processed/ports.txt  (host:port, one per line, deduped)
        data/processed/ports_full.jsonl (structured per-host results, where available)
"""

from __future__ import annotations
import json
import os
import subprocess
from typing import Iterable, Set

from utils.dedupe import save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("scan.ports")


def _run_cli(binary: str, args: list[str], stdin_data: str | None = None, timeout: int = 600) -> str:
    try:
        proc = subprocess.run(
            [binary, *args], input=stdin_data,
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            log.warning(f"{binary} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out after {timeout}s")
        return ""


def _authorized_or_bail(cfg: Config) -> bool:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to port scan. Set "
            "target.authorized: true in settings.yaml only once you have "
            "confirmed you own this target or hold explicit written "
            "authorization (bug bounty scope doc, pentest contract, etc.)."
        )
        return False
    return True


# ------------------------------------------------------------------ naabu --
def naabu_scan(cfg: Config, hosts: Iterable[str], top_ports: int = 1000) -> Set[str]:
    """Fast top-ports sweep. Input: bare hostnames or IPs (not URLs)."""
    if not _authorized_or_bail(cfg):
        return set()

    hosts = list(hosts)
    if not hosts:
        log.warning("naabu_scan called with empty host list")
        return set()

    binary = cfg.tool_path("naabu")
    args = ["-silent", "-top-ports", str(top_ports), "-json"]
    out = _run_cli(binary, args, stdin_data="\n".join(hosts), timeout=900)

    results: Set[str] = set()
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if host and port:
            results.add(f"{host}:{port}")

    log.info(f"naabu: {len(results)} open host:port pairs across {len(hosts)} targets")
    return results


# --------------------------------------------------------------- rustscan --
def rustscan_confirm(cfg: Config, hosts: Iterable[str]) -> Set[str]:
    """
    Fast full 1-65535 confirm pass, meant to be run only on the (smaller)
    set of hosts naabu already flagged as interesting — not the whole
    original list. Keeps total scan time reasonable.
    """
    if not _authorized_or_bail(cfg):
        return set()

    hosts = list(hosts)
    if not hosts:
        return set()

    binary = cfg.tool_path("rustscan")
    results: Set[str] = set()

    for host in hosts:
        out = _run_cli(
            binary,
            ["-a", host, "--ulimit", "5000", "-g"],  # -g = greppable output
            timeout=300,
        )
        for line in out.splitlines():
            # greppable format roughly: "Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///,80/open/tcp..."
            if "Ports:" not in line:
                continue
            try:
                ports_part = line.split("Ports:", 1)[1]
                for entry in ports_part.split(","):
                    port = entry.strip().split("/")[0]
                    if port.isdigit():
                        results.add(f"{host}:{port}")
            except IndexError:
                continue

    log.info(f"rustscan: confirmed {len(results)} host:port pairs across {len(hosts)} hosts")
    return results


# --------------------------------------------------------------- masscan --
def masscan_ranges(cfg: Config, cidrs: Iterable[str], ports: str = "1-65535",
                    rate: int = 1000, explicit_confirm: bool = False) -> Set[str]:
    """
    Only for large CIDR ranges, and only ever runs if explicit_confirm=True
    is passed by the caller — this is a deliberate second gate on top of
    cfg.authorized, since masscan at high rates against ranges you don't
    fully control (e.g. a /16 that isn't entirely the target's) can cause
    real collateral damage / abuse complaints.
    """
    if not _authorized_or_bail(cfg):
        return set()

    if not explicit_confirm:
        log.error(
            "masscan_ranges called without explicit_confirm=True. This is "
            "the loudest/highest-risk tool in the cascade — call it with "
            "explicit_confirm=True only after verifying every CIDR in the "
            "input actually belongs to the authorized target, not shared "
            "hosting/CDN space."
        )
        return set()

    cidrs = list(cidrs)
    if not cidrs:
        return set()

    binary = cfg.tool_path("masscan")
    results: Set[str] = set()

    for cidr in cidrs:
        out = _run_cli(
            binary,
            [cidr, "-p", ports, "--rate", str(rate), "-oL", "-"],
            timeout=1800,
        )
        for line in out.splitlines():
            # masscan -oL format: "open tcp 80 1.2.3.4 <timestamp>"
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "open":
                port, ip = parts[2], parts[3]
                results.add(f"{ip}:{port}")

    log.info(f"masscan: {len(results)} open host:port pairs across {len(cidrs)} ranges")
    return results


def run_port_scan_stage(cfg: Config, hosts: Iterable[str]) -> Set[str]:
    """
    Default cascade for Step 6: naabu sweep -> rustscan confirm on the
    subset naabu flagged. masscan is NOT called here automatically;
    invoke masscan_ranges() directly if you need large-range coverage.
    """
    naabu_results = naabu_scan(cfg, hosts)

    interesting_hosts = sorted({r.split(":")[0] for r in naabu_results})
    rustscan_results = rustscan_confirm(cfg, interesting_hosts) if interesting_hosts else set()

    merged = naabu_results | rustscan_results
    out_path = os.path.join(cfg.processed_dir, "ports.txt")
    save_set(out_path, merged, )
    log.info(f"Port scan stage complete: {len(merged)} unique host:port pairs -> {out_path}")
    return merged
