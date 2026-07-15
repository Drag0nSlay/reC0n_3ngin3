"""
modules/secrets/github_leakage.py

Phase 5 / Step 12 — GitHub Leakage.
Searches public GitHub (code search + optionally cloned repos scanned
with trufflehog) for secrets mentioning the target domain/org. This
queries GitHub's API/public repos, not the target's own infrastructure,
so — like Phase 1's passive sources — it's not gated on cfg.authorized.
It DOES require api_keys.github_token to do anything meaningful.

Tools:
  - gitGraber / GitDorker: dork-style search wrappers over GitHub code search
  - trufflehog: deep-scans git history of specific repos for secrets
    (only meaningfully invoked once you have a list of repos to point it at)

Output: data/processed/github_secrets.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import Iterable, List

import requests

from utils.logger import get_logger
from core.config import Config

log = get_logger("secrets.github_leakage")

# A conservative default dork set — mirrors common GitDorker categories.
# Extend cautiously; overly broad dorks just generate noise + rate-limit hits.
DEFAULT_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" .env',
    '"{domain}" config',
]


def _run_cli(binary: str, args: list[str], timeout: int = 300) -> str:
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            log.warning(f"{binary} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout
    except FileNotFoundError:
        log.info(f"{binary}: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning(f"{binary}: timed out after {timeout}s")
        return ""


def github_code_search(cfg: Config, dorks: List[str] | None = None) -> List[str]:
    """
    Built-in fallback that hits GitHub's code search API directly
    (no external tool required, just api_keys.github_token).
    Returns raw result lines: "repo | path | html_url".
    """
    token = cfg.api_key("github_token")
    if not token:
        log.info("GitHub: no token configured, skipping code search")
        return []

    dorks = dorks or [d.format(domain=cfg.domain) for d in DEFAULT_DORKS]
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    results: List[str] = []

    for dork in dorks:
        try:
            r = requests.get(
                "https://api.github.com/search/code",
                headers=headers, params={"q": dork, "per_page": 30},
                timeout=cfg.http_timeout,
            )
            r.raise_for_status()
            body = r.json()
            for item in body.get("items", []):
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                html_url = item.get("html_url", "?")
                results.append(f"{repo} | {path} | {html_url}")
        except Exception as e:
            log.warning(f"GitHub code search failed for dork {dork!r}: {e}")

    log.info(f"GitHub code search: {len(results)} raw hits across {len(dorks)} dorks")
    return results


def gitgraber_scan(cfg: Config, keywords: List[str] | None = None) -> str:
    binary = cfg.tool_path("gitgraber")
    keywords = keywords or [cfg.domain]
    return _run_cli(binary, ["-k", *keywords] + cfg.extra_args("gitgraber"))


def gitdorker_scan(cfg: Config) -> str:
    binary = cfg.tool_path("gitdorker")
    token = cfg.api_key("github_token")
    args = ["-tf", token] if token else []
    args += ["-d", cfg.domain]
    return _run_cli(binary, args + cfg.extra_args("gitdorker"))


def trufflehog_scan_repo(cfg: Config, repo_url: str) -> str:
    """Deep-scan a specific repo's git history — run only on repos flagged as relevant."""
    binary = cfg.tool_path("trufflehog")
    return _run_cli(binary, ["git", repo_url, "--only-verified"] + cfg.extra_args("trufflehog"), timeout=600)


def run_github_leakage_stage(cfg: Config, flagged_repos: Iterable[str] | None = None) -> List[str]:
    """
    Orchestrates Step 12: code-search dorking first (cheap, broad), then
    optional deep trufflehog pass on any repos you've decided are worth
    the extra time (pass flagged_repos explicitly — no auto-cloning).
    """
    findings: List[str] = []

    findings.extend(github_code_search(cfg))
    gg_out = gitgraber_scan(cfg)
    if gg_out:
        findings.extend(l.strip() for l in gg_out.splitlines() if l.strip())
    gd_out = gitdorker_scan(cfg)
    if gd_out:
        findings.extend(l.strip() for l in gd_out.splitlines() if l.strip())

    for repo in (flagged_repos or []):
        th_out = trufflehog_scan_repo(cfg, repo)
        if th_out:
            findings.extend(l.strip() for l in th_out.splitlines() if l.strip())

    out_path = os.path.join(cfg.processed_dir, "github_secrets.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(findings))) + ("\n" if findings else ""))

    log.info(f"GitHub leakage stage: {len(set(findings))} findings -> {out_path}")
    return findings
