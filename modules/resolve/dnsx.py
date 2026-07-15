"""
modules/resolve/dnsx.py

Phase 2 / Step 4 — DNS Resolution.
Resolves the deduped subdomain list from Phase 1 down to hosts that
actually have DNS records, using dnsx. This is the first step where we
query the *target's* authoritative/recursive resolvers directly, so it
is gated on cfg.authorized just like brute-force in Phase 1.

Also does wildcard-DNS filtering: dnsx's -wd flag removes hosts that
only resolve because of a wildcard record, which otherwise pollutes
every downstream stage with junk hosts.

Output: data/processed/resolved.txt  (one "host [A/CNAME records]" per line via -resp)
        data/processed/resolved_hosts_only.txt  (bare hostnames, for chaining)
"""

from __future__ import annotations
import os
import subprocess
from typing import Set

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("resolve.dnsx")


def _run_cli(binary: str, args: list[str], stdin_data: str, timeout: int = 600) -> str:
    try:
        proc = subprocess.run(
            [binary, *args],
            input=stdin_data,
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


def resolve_domains(cfg: Config, domains: Set[str]) -> dict:
    """
    Runs dnsx over the given domain set. Returns dict with:
      - 'resolved_raw': full dnsx -resp output lines (host + records)
      - 'hosts': bare set of hostnames that resolved
    """
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to send DNS resolution "
            "queries to the target's infrastructure. Set target.authorized: "
            "true in settings.yaml once you've confirmed you're in scope."
        )
        return {"resolved_raw": [], "hosts": set()}

    if not domains:
        log.warning("resolve_domains called with empty input set")
        return {"resolved_raw": [], "hosts": set()}

    binary = cfg.tool_path("dnsx") if hasattr(cfg, "tool_path") else "dnsx"
    stdin_data = "\n".join(sorted(domains))

    args = ["-silent", "-resp", "-wd", cfg.domain] + cfg.extra_args("dnsx")  # -wd = wildcard filter against root domain
    out = _run_cli(binary, args, stdin_data)

    raw_lines = [l for l in out.splitlines() if l.strip()]
    hosts: Set[str] = set()
    for line in raw_lines:
        # dnsx -resp format: "host.example.com [1.2.3.4]"
        host = line.split(" ", 1)[0].strip()
        if host:
            hosts.add(host)

    hosts = dedupe_lines(hosts)

    raw_path = os.path.join(cfg.processed_dir, "resolved.txt")
    hosts_path = os.path.join(cfg.processed_dir, "resolved_hosts_only.txt")
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write("\n".join(raw_lines) + ("\n" if raw_lines else ""))
    save_set(hosts_path, hosts)

    log.info(f"dnsx resolved {len(hosts)}/{len(domains)} input domains -> {hosts_path}")
    return {"resolved_raw": raw_lines, "hosts": hosts}
