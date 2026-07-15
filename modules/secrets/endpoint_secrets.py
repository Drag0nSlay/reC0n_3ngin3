"""
modules/secrets/endpoint_secrets.py

Phase 5 / Step 11 — Endpoint + Secret Discovery.
This step fetches the actual contents of discovered .js files from the
target and scans them for embedded API endpoints and hard-coded secrets
— real HTTP requests to the target, so it's gated on cfg.authorized.

Tries external tools first (LinkFinder, SecretFinder, Mantra) if
configured/installed; always falls back to a built-in lightweight
regex scanner (same idea as gitleaks/trufflehog "generic rules") so the
step still produces useful output with zero extra installs.

Output: data/processed/endpoints.txt
        data/processed/secrets.txt   (pattern name + redacted match + source URL)
"""

from __future__ import annotations
import os
import re
import subprocess
from typing import Iterable, List, Set

import requests

from utils.dedupe import dedupe_lines, save_set
from utils.logger import get_logger
from core.config import Config

log = get_logger("secrets.endpoint_secrets")


# Generic high-confidence secret patterns (same spirit as gitleaks'
# "generic-api-key" style rules — deliberately conservative to keep the
# false-positive rate manageable). Matches are redacted before writing.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "generic_bearer_jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    "generic_api_key_assignment": re.compile(
        r"(?i)(api[_-]?key|secret|token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]"
    ),
}

# Loose endpoint-path finder — mirrors what LinkFinder looks for: quoted
# strings that look like absolute or relative API paths.
ENDPOINT_PATTERN = re.compile(
    r"""["'](\/[a-zA-Z0-9_\-/{}.]{2,}|https?://[a-zA-Z0-9_\-./]+/[a-zA-Z0-9_\-/{}.]*)["']"""
)


def _redact(match: str, keep: int = 4) -> str:
    if len(match) <= keep * 2:
        return "*" * len(match)
    return match[:keep] + "..." + match[-keep:]


def _fetch_js(url: str, timeout: int) -> str:
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (reC0n_3ngin3)"})
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"Failed to fetch {url}: {e}")
        return ""


def _builtin_scan(js_text: str, source_url: str) -> tuple[Set[str], List[str]]:
    endpoints: Set[str] = set()
    for m in ENDPOINT_PATTERN.finditer(js_text):
        endpoints.add(m.group(1))

    secrets: List[str] = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(js_text):
            secrets.append(f"{name} | {_redact(m.group(0))} | {source_url}")

    return endpoints, secrets


def _run_external_tool(binary: str, args: list[str], timeout: int = 60) -> str:
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out")
        return ""


def analyze_js_files(cfg: Config, js_urls: Iterable[str]) -> dict:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to fetch JS content from "
            "the target. Set target.authorized: true once in scope."
        )
        return {"endpoints": set(), "secrets": []}

    js_urls = list(js_urls)
    if not js_urls:
        log.warning("analyze_js_files called with empty JS URL list")
        return {"endpoints": set(), "secrets": []}

    all_endpoints: Set[str] = set()
    all_secrets: List[str] = []

    linkfinder_bin = cfg.tool_path("linkfinder")
    secretfinder_bin = cfg.tool_path("secretfinder")
    mantra_bin = cfg.tool_path("mantra")

    for url in js_urls:
        js_text = _fetch_js(url, cfg.http_timeout)
        if not js_text:
            continue

        # Try external tools if present (best-effort; they may expect a
        # temp file or different invocation style depending on version —
        # adjust args to match your installed forks).
        lf_out = _run_external_tool(linkfinder_bin, ["-i", url, "-o", "cli"] + cfg.extra_args("linkfinder"))
        sf_out = _run_external_tool(secretfinder_bin, ["-i", url, "-o", "cli"] + cfg.extra_args("secretfinder"))
        mantra_out = _run_external_tool(mantra_bin, [url] + cfg.extra_args("mantra"))

        for line in (lf_out + "\n" + mantra_out).splitlines():
            line = line.strip()
            if line.startswith(("/", "http")):
                all_endpoints.add(line)

        for line in sf_out.splitlines():
            line = line.strip()
            if line:
                all_secrets.append(f"secretfinder | {line} | {url}")

        # Always run the built-in fallback too — cheap, and catches things
        # external tools miss or that aren't installed at all.
        endpoints, secrets = _builtin_scan(js_text, url)
        all_endpoints |= endpoints
        all_secrets.extend(secrets)

    all_endpoints = dedupe_lines(all_endpoints, normalize=False)

    endpoints_path = os.path.join(cfg.processed_dir, "endpoints.txt")
    secrets_path = os.path.join(cfg.processed_dir, "secrets.txt")
    save_set(endpoints_path, all_endpoints, )
    with open(secrets_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(all_secrets))) + ("\n" if all_secrets else ""))

    log.info(f"endpoint discovery: {len(all_endpoints)} -> {endpoints_path}")
    log.info(f"secret discovery: {len(set(all_secrets))} findings (redacted) -> {secrets_path}")

    return {"endpoints": all_endpoints, "secrets": all_secrets}
