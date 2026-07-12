"""
modules/cloud/bucket_discovery.py

Phase 8 / Step 20 — Bucket Discovery.

  - awscli / lazys3 / S3Scanner: guess bucket names derived from the
    target's domain/org and probe AWS S3 directly for existence/
    public-readability. This is active probing (even though it's aimed
    at AWS's infrastructure, not the target's own servers, the intent
    and scope is target-derived) — gated on cfg.authorized.
  - greyhatwarfare: queries a third-party index of *already-discovered*
    open buckets/files. Pure API lookup, no probing of our own —
    ungated like other passive intel sources. Requires an API key if
    you have one; public search also works unauthenticated for basic queries.

Output: data/processed/buckets.txt
"""

from __future__ import annotations
import os
import subprocess
from typing import List

import requests

from utils.logger import get_logger
from core.config import Config

log = get_logger("cloud.buckets")

# Common bucket-name permutations derived from an org/domain keyword.
DEFAULT_SUFFIXES = ["", "-backup", "-dev", "-staging", "-prod", "-assets", "-media",
                     "-static", "-uploads", "-data", "-files", "-logs", "-private"]


def _candidate_names(keyword: str) -> List[str]:
    keyword = keyword.split(".")[0]  # strip TLD if a domain was passed
    return sorted({f"{keyword}{suffix}" for suffix in DEFAULT_SUFFIXES})


def _authorized_or_bail(cfg: Config) -> bool:
    if not cfg.authorized:
        log.error(
            "target.authorized is False — refusing to actively probe AWS "
            "for buckets derived from the target's name. Set "
            "target.authorized: true once in scope."
        )
        return False
    return True


def awscli_bucket_check(cfg: Config, keyword: str | None = None) -> List[str]:
    """Uses `aws s3 ls s3://<bucket>` (no creds needed for public buckets) to check existence/access."""
    if not _authorized_or_bail(cfg):
        return []

    keyword = keyword or cfg.domain
    hits: List[str] = []

    for name in _candidate_names(keyword):
        try:
            proc = subprocess.run(
                ["aws", "s3", "ls", f"s3://{name}", "--no-sign-request"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode == 0:
                hits.append(f"{name} | ACCESSIBLE (public listing) | aws-s3")
            elif "AccessDenied" in proc.stderr:
                hits.append(f"{name} | EXISTS (access denied) | aws-s3")
        except FileNotFoundError:
            log.info("awscli: not installed, skipping")
            break
        except subprocess.TimeoutExpired:
            continue

    log.info(f"awscli bucket check: {len(hits)} hits across {len(_candidate_names(keyword))} candidates")
    return hits


def lazys3_scan(cfg: Config, keyword: str | None = None) -> str:
    if not _authorized_or_bail(cfg):
        return ""
    binary = cfg.tool_path("lazys3") if hasattr(cfg, "tool_path") else "lazys3"
    keyword = keyword or cfg.domain.split(".")[0]
    try:
        proc = subprocess.run([binary, keyword], capture_output=True, text=True, timeout=300)
        return proc.stdout
    except FileNotFoundError:
        log.info("lazys3: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning("lazys3: timed out")
        return ""


def s3scanner_scan(cfg: Config, keyword: str | None = None) -> str:
    if not _authorized_or_bail(cfg):
        return ""
    binary = cfg.tool_path("s3scanner") if hasattr(cfg, "tool_path") else "s3scanner"
    keyword = keyword or cfg.domain
    candidates = _candidate_names(keyword)
    try:
        proc = subprocess.run(
            [binary, "scan", "--bucket-file", "-"],
            input="\n".join(candidates),
            capture_output=True, text=True, timeout=300,
        )
        return proc.stdout
    except FileNotFoundError:
        log.info("s3scanner: not installed, skipping")
        return ""
    except subprocess.TimeoutExpired:
        log.warning("s3scanner: timed out")
        return ""


def greyhatwarfare_search(cfg: Config, keyword: str | None = None) -> List[str]:
    """
    Queries greyhatwarfare.com's public API for already-indexed open
    buckets/files matching the keyword. Pure third-party lookup — no
    probing of our own, so ungated.
    """
    keyword = keyword or cfg.domain
    url = "https://buckets.grayhatwarfare.com/api/v2/files"
    params = {"keywords": keyword, "limit": 50}

    try:
        r = requests.get(url, params=params, timeout=cfg.http_timeout)
        r.raise_for_status()
        body = r.json()
    except Exception as e:
        log.warning(f"greyhatwarfare search failed: {e}")
        return []

    hits = []
    for item in body.get("files", []):
        bucket = item.get("bucket", "?")
        filename = item.get("filename", "?")
        hits.append(f"{bucket} | {filename} | greyhatwarfare-index")

    log.info(f"greyhatwarfare: {len(hits)} indexed hits for keyword {keyword!r}")
    return hits


def run_bucket_discovery_stage(cfg: Config, keyword: str | None = None) -> List[str]:
    findings: List[str] = []

    # Passive first (principle #1): third-party index before active probing
    findings.extend(greyhatwarfare_search(cfg, keyword))

    # Active probing, gated
    findings.extend(awscli_bucket_check(cfg, keyword))
    for line in lazys3_scan(cfg, keyword).splitlines():
        line = line.strip()
        if line:
            findings.append(f"{line} | lazys3")
    for line in s3scanner_scan(cfg, keyword).splitlines():
        line = line.strip()
        if line:
            findings.append(f"{line} | s3scanner")

    out_path = os.path.join(cfg.processed_dir, "buckets.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(findings))) + ("\n" if findings else ""))

    log.info(f"bucket discovery: {len(set(findings))} total findings -> {out_path}")
    return findings