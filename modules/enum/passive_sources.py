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

Every source function accepts an optional `domain` override (defaults to
cfg.domain) and `prefix` for the raw output filename — this lets
modules.enum.recursive_enum re-run the same trusted sources against a
discovered sub-root without clobbering the primary run's raw files.
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


def _write_raw(cfg: Config, name: str, domains: Set[str], prefix: str = "") -> None:
    fname = f"{prefix}{name}.txt" if prefix else f"{name}.txt"
    path = os.path.join(cfg.raw_dir, fname)
    save_set(path, domains)
    log.info(f"{name}: {len(domains)} domains -> {path}")


# ---------------------------------------------------------------- crt.sh ----
def crtsh(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    domain = domain or cfg.domain
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
    _write_raw(cfg, "crtsh", result, prefix)
    return result


# ------------------------------------------------------------ VirusTotal ----
def virustotal(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    key = cfg.api_key("virustotal")
    if not key:
        log.info("VirusTotal: no API key configured, skipping")
        return set()

    domain = domain or cfg.domain
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
    _write_raw(cfg, "virustotal", out, prefix)
    return out


# ----------------------------------------------------------------- Chaos ----
def chaos(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    key = cfg.api_key("chaos")
    if not key:
        log.info("Chaos: no API key configured, skipping")
        return set()

    domain = domain or cfg.domain
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
    _write_raw(cfg, "chaos", out, prefix)
    return out


# -------------------------------------------------------- GitHub search ----
def github_subdomains(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    """
    Greps public GitHub code search for literal subdomain mentions.
    Cheap, high-signal source for internal/staging hosts leaked in configs.
    """
    token = cfg.api_key("github_token")
    if not token:
        log.info("GitHub: no token configured, skipping")
        return set()

    domain = domain or cfg.domain
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
    _write_raw(cfg, "github", out, prefix)
    return out


# -------------------------------------------------------- amass helpers ----
_amass_version_cache: dict = {}


def _detect_amass_version(binary: str) -> str | None:
    """Detect amass major version (returns '3', '4', or None on failure).

    Caches the result per binary path so we only shell out once per run.
    amass v3: `amass -version` prints "v3.x.x"
    amass v4 (OWASP fork): `amass -version` or `amass --version` prints
    something containing "v4" or "OWASP Amass v4".
    """
    if binary in _amass_version_cache:
        return _amass_version_cache[binary]

    version = None
    for flag in ["-version", "--version", "version"]:
        try:
            proc = subprocess.run(
                [binary, flag], capture_output=True, text=True, timeout=10
            )
            combined = (proc.stdout + proc.stderr).lower()
            if "v4" in combined or "owasp" in combined:
                version = "4"
                break
            elif "v3" in combined or "amass v" in combined:
                version = "3"
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            break

    _amass_version_cache[binary] = version
    if version:
        log.info(f"amass version detected: v{version}")
    return version


def _diagnose_amass_error(stderr: str, binary: str) -> None:
    """Parse common amass error patterns and log actionable diagnostics."""
    stderr_lower = stderr.lower()

    if "datasources" in stderr_lower or "config" in stderr_lower:
        log.warning(
            f"{binary}: amass config/datasources issue detected. "
            "If you're on amass v4 (OWASP), it expects a datasources.yaml "
            "file (not the old config.ini). See: "
            "https://github.com/owasp-amass/amass/blob/master/examples/datasources.yaml"
        )
    elif "nonetype" in stderr_lower or "not iterable" in stderr_lower:
        log.warning(
            f"{binary}: amass returned a NoneType/iteration error — this usually "
            "means a data source returned no results or the API response was empty. "
            "Not a bug in reC0n_3ngin3 — amass's internal error handling surfaced it."
        )
    elif "timeout" in stderr_lower or "deadline" in stderr_lower:
        log.warning(
            f"{binary}: amass hit a timeout or deadline. Consider increasing the "
            "timeout or reducing the scope."
        )
    elif stderr.strip():
        log.warning(f"{binary} stderr: {stderr.strip()[:500]}")


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


def subfinder(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    domain = domain or cfg.domain
    binary = cfg.tool_path("subfinder")
    out = _run_cli(binary, ["-d", domain, "-silent", "-all"] + cfg.extra_args("subfinder"))
    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "subfinder", result, prefix)
    return result


def assetfinder(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    domain = domain or cfg.domain
    binary = cfg.tool_path("assetfinder")
    out = _run_cli(binary, ["--subs-only", domain] + cfg.extra_args("assetfinder"))
    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "assetfinder", result, prefix)
    return result


def amass_passive(cfg: Config, domain: str | None = None, prefix: str = "") -> Set[str]:
    domain = domain or cfg.domain
    binary = cfg.tool_path("amass")

    # Detect version for diagnostics (does not change passive-mode args —
    # `amass enum -passive -d <domain>` works on both v3 and v4)
    version = _detect_amass_version(binary)

    try:
        proc = subprocess.run(
            [binary, "enum", "-passive", "-d", domain] + cfg.extra_args("amass"),
            capture_output=True, text=True, timeout=600,  # amass is notoriously slow
        )
        if proc.returncode != 0:
            _diagnose_amass_error(proc.stderr, binary)
        out = proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed / not on PATH, skipping")
        out = ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary} enum -passive: timed out after 600s")
        out = ""

    result = dedupe_lines(out.splitlines())
    _write_raw(cfg, "amass", result, prefix)
    return result


def amass_intel_org(cfg: Config, org_name: str | None = None) -> Set[str]:
    """
    `amass intel -org "Org Name"` — a genuinely different discovery mode
    from amass enum: instead of enumerating subdomains of ONE root
    domain, it searches WHOIS/registry data for everything registered
    under an organization's name, surfacing ASNs and netblocks the org
    owns — which may point to entirely separate root domains you'd
    otherwise miss.

    Important: this does NOT return subdomains directly, so its output
    is written to a separate org_intel.txt file rather than merged into
    final_subdomains.txt — treat it as a lead to manually pivot from
    (e.g. feed a newly discovered root domain back into this pipeline
    as its own target.domain run), not as confirmed pipeline output.

    Requires target.org_name in settings.yaml (falls back to cfg.domain's
    registrable name if not set, which is a weaker guess).
    """
    org_name = org_name or cfg.org_name or cfg.domain.split(".")[0]
    binary = cfg.tool_path("amass")

    version = _detect_amass_version(binary)

    try:
        proc = subprocess.run(
            [binary, "intel", "-org", org_name] + cfg.extra_args("amass"),
            capture_output=True, text=True, timeout=600,
        )
        if proc.returncode != 0:
            _diagnose_amass_error(proc.stderr, binary)
        out = proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed / not on PATH, skipping amass intel")
        out = ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary} intel -org: timed out after 600s")
        out = ""

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    result = set(lines)

    out_path = os.path.join(cfg.raw_dir, "org_intel.txt")
    save_set(out_path, result)
    log.info(
        f"amass intel -org '{org_name}': {len(result)} raw ASN/netblock/whois lines -> {out_path} "
        f"(NOT auto-merged into subdomains — review manually)"
    )
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

# Fast, API-only sources (no slow/timeout-prone CLI binaries) — used by
# recursive_enum so recursing into N sub-roots doesn't spend 5+ minutes
# per sub-root waiting on amass/subfinder.
FAST_SOURCES = {
    "crtsh": crtsh,
    "virustotal": virustotal,
    "chaos": chaos,
}


def run_all_passive(
    cfg: Config,
    max_workers: int | None = None,
    domain: str | None = None,
    prefix: str = "",
    sources: dict | None = None,
) -> Set[str]:
    """Fan out passive sources concurrently (principle #4), merge + dedupe.

    domain: override cfg.domain (used for recursive enumeration sub-roots)
    prefix: namespaces raw output filenames so recursive runs don't
            overwrite the primary run's data/raw/*.txt files
    sources: which source functions to run — defaults to ALL_SOURCES;
             recursive_enum passes FAST_SOURCES to keep sub-root
             recursion fast
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    workers = max_workers or cfg.max_workers
    sources = sources or ALL_SOURCES
    merged: Set[str] = set()

    # NOTE: plain `with ThreadPoolExecutor(...) as pool:` blocks on Ctrl+C —
    # the context manager's __exit__ calls shutdown(wait=True) unconditionally,
    # so pressing Ctrl+C appears to "not work" until every in-flight thread
    # (a slow HTTP request, a subprocess with a multi-minute timeout) finishes
    # on its own. Handling KeyboardInterrupt explicitly and cancelling
    # pending futures makes Ctrl+C actually stop the run promptly.
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(fn, cfg, domain, prefix): name for name, fn in sources.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                merged |= fut.result()
            except Exception as e:
                log.warning(f"Source {name} raised: {e}")
    except KeyboardInterrupt:
        log.warning("Interrupted — cancelling remaining passive-source lookups...")
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)

    out_name = f"{prefix}all_subdomains_raw.txt" if prefix else "all_subdomains_raw.txt"
    out_path = os.path.join(cfg.raw_dir, out_name)
    save_set(out_path, merged)
    log.info(f"Passive enumeration total: {len(merged)} unique domains -> {out_path}")
    return merged
