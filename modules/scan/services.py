"""
modules/scan/services.py

Phase 3 / Step 7 — Service Enumeration.
Runs `nmap -sV -sC` (version detection + default safe scripts) — but
deliberately NOT against every open port found in Step 6. nmap -sC/-sV
is slow and noisy; running it host-by-host across a large surface wastes
time and generates a lot of target-side log noise for little gain.

Instead this module expects a curated "high-value" host list, and
provides `select_high_value_hosts()` to help build that list from the
Step 6 port-scan results + Phase 2 httpx tech-detection output, using
simple heuristics (admin/db/remote-access ports, auth-walled or
fingerprinted-tech web hosts). You can always pass your own list too —
the heuristic is a starting point, not a substitute for judgment.

Output: data/processed/services.txt        (human-readable nmap -oN style, concatenated)
        data/processed/services_full.xml   (raw -oX output per host, concatenated w/ separators)
"""

from __future__ import annotations
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Iterable, List, Set

from utils.logger import get_logger
from core.config import Config

log = get_logger("scan.services")

# Ports commonly worth a deeper look: remote admin, databases, mail, etc.
HIGH_VALUE_PORTS = {
    21, 22, 23, 25, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 5985, 6379, 8443, 9200, 27017,
}


def select_high_value_hosts(
    port_pairs: Iterable[str],
    httpx_records: List[dict] | None = None,
    max_hosts: int = 50,
) -> List[str]:
    """
    port_pairs: iterable of "host:port" strings (from Step 6 ports.txt)
    httpx_records: optional list of parsed httpx JSON records (Step 5)
                   used to also flag auth-walled (401/403) or
                   tech-fingerprinted web hosts as high value.
    Returns a capped list of bare hostnames/IPs worth deep nmap scanning.
    """
    flagged: Set[str] = set()

    for pair in port_pairs:
        if ":" not in pair:
            continue
        host, _, port = pair.rpartition(":")
        if port.isdigit() and int(port) in HIGH_VALUE_PORTS:
            flagged.add(host)

    if httpx_records:
        for rec in httpx_records:
            status = rec.get("status_code")
            tech = rec.get("tech")
            host = rec.get("host") or rec.get("input")
            if not host:
                continue
            if status in (401, 403) or tech:
                flagged.add(host)

    result = sorted(flagged)[:max_hosts]
    log.info(f"select_high_value_hosts: flagged {len(flagged)} hosts, capped to {len(result)}")
    return result


def _authorized_or_bail(cfg: Config) -> bool:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to run nmap service "
            "enumeration against the target. Set target.authorized: true "
            "only once authorization is confirmed."
        )
        return False
    return True


def nmap_service_scan(cfg: Config, hosts: List[str], ports: str | None = None,
                       timeout_per_host: int = 300) -> dict:
    """
    Runs `nmap -sV -sC` per host (optionally restricted to specific ports
    via -p), writing both a concatenated human-readable log and raw XML
    per host for structured parsing.
    """
    if not _authorized_or_bail(cfg):
        return {"text": "", "hosts_scanned": []}

    if not hosts:
        log.warning("nmap_service_scan called with empty host list")
        return {"text": "", "hosts_scanned": []}

    binary = cfg.tool_path("nmap") if hasattr(cfg, "tool_path") else "nmap"
    text_path = os.path.join(cfg.processed_dir, "services.txt")
    xml_path = os.path.join(cfg.processed_dir, "services_full.xml")

    all_text: list[str] = []
    all_xml: list[str] = []
    scanned: list[str] = []

    for host in hosts:
        args = ["-sV", "-sC", "-oN", "-", "-oX", "-", host] + cfg.extra_args("nmap")
        if ports:
            args = ["-sV", "-sC", "-p", ports, "-oN", "-", "-oX", "-", host] + cfg.extra_args("nmap")

        try:
            proc = subprocess.run(
                [binary, *args], capture_output=True, text=True,
                timeout=timeout_per_host,
            )
            if proc.returncode != 0:
                log.warning(f"nmap exited {proc.returncode} for {host}: {proc.stderr.strip()[:300]}")
        except FileNotFoundError:
            log.info("nmap: not installed, aborting service enumeration")
            break
        except subprocess.TimeoutExpired:
            log.warning(f"nmap: timed out on {host} after {timeout_per_host}s, skipping")
            continue

        # -oN and -oX both come out on stdout intermixed when both are "-";
        # nmap actually only supports one "-" stream at a time in some
        # versions, so fall back to two separate invocations if needed.
        stdout = proc.stdout
        if "<?xml" in stdout:
            xml_part = stdout[stdout.index("<?xml"):]
            text_part = stdout[:stdout.index("<?xml")]
        else:
            xml_part, text_part = "", stdout

        all_text.append(f"# === {host} ===\n{text_part.strip()}\n")
        if xml_part:
            all_xml.append(xml_part)
        scanned.append(host)

    with open(text_path, "w", encoding="utf-8") as f:
        f.write("\n".join(all_text))
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write("\n<!-- next host -->\n".join(all_xml))

    log.info(f"nmap service scan complete: {len(scanned)}/{len(hosts)} hosts -> {text_path}")
    return {"text": "\n".join(all_text), "hosts_scanned": scanned}


def parse_nmap_xml(xml_blob: str) -> List[dict]:
    """
    Best-effort parse of one or more concatenated nmap -oX blobs into a
    flat list of {host, port, protocol, service, product, version} dicts.
    Skips any chunk that fails to parse rather than raising.
    """
    results: List[dict] = []
    for chunk in xml_blob.split("\n<!-- next host -->\n"):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError as e:
            log.warning(f"nmap XML parse error: {e}")
            continue

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host_addr = addr_el.get("addr") if addr_el is not None else None
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                port_id = port_el.get("portid")
                protocol = port_el.get("protocol")
                service_el = port_el.find("service")
                results.append({
                    "host": host_addr,
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                })
    return results
