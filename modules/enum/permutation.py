"""
modules/enum/permutation.py

Extends Phase 1/3 with a permutation (alteration) engine: instead of only
brute-forcing a static wordlist, generate smart candidate labels derived
from keywords already seen in discovered subdomains, combined with a
curated list of common naming patterns (dev, staging, api, v2, etc.).

Critical design decision — false positives:
  Permutations are GUESSES, not confirmed subdomains. This module NEVER
  writes them into final_subdomains.txt directly. It only writes a
  candidate wordlist file. The orchestrator feeds that wordlist into the
  EXISTING Step 3 shuffledns brute-force step, which performs real DNS
  resolution — only permutations that actually resolve make it into the
  final output. This reuses the pipeline's existing verification step
  rather than inventing a new one, and keeps the "no unverified guesses
  in final output" guarantee intact.

  Consequence: permutation candidates are only ever confirmed when
  target.authorized: true (since DNS resolution is an active step,
  already gated). With authorized: false, this module still safely
  generates the candidate file (offline, no network) for inspection,
  but nothing from it reaches final_subdomains.txt.

Bounds (to avoid wordlist/DNS-query explosion):
  - enumeration.permutation_max_candidates hard-caps total generated
    labels regardless of how many keywords/terms are combined.
  - Keywords are extracted only from the leftmost label of each
    discovered subdomain (not full hostnames) — keeps the term pool
    small and relevant.

Output: data/raw/permutation_wordlist.txt (labels only, shuffledns
        input format — one label per line, NOT full hostnames)
"""

from __future__ import annotations
import os
import re
from typing import List, Set

from utils.logger import get_logger
from core.config import Config

log = get_logger("enum.permutation")

DEFAULT_PERMUTATION_TERMS = [
    "dev", "staging", "test", "uat", "qa", "admin", "internal", "vpn",
    "api", "beta", "old", "new", "backup", "prod", "demo", "sandbox",
    "v1", "v2", "portal", "gateway", "app", "mobile", "secure", "cdn",
]

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def _extract_keywords(subdomains: Set[str], root_domain: str) -> Set[str]:
    """Pulls the leftmost label off each subdomain as a candidate keyword,
    e.g. 'api' from 'api.example.com'. Filters out junk (wildcards, the
    root domain itself, single-char noise)."""
    keywords = set()
    for sub in subdomains:
        if sub == root_domain or not sub.endswith(root_domain):
            continue
        remainder = sub[: -(len(root_domain) + 1)] if sub.endswith("." + root_domain) else ""
        if not remainder:
            continue
        label = remainder.split(".")[0].lower()
        if _LABEL_RE.match(label) and len(label) > 2 and label != "*":
            keywords.add(label)
    return keywords


def generate_permutation_labels(
    cfg: Config,
    subdomains: Set[str],
    terms: List[str] | None = None,
    max_candidates: int | None = None,
) -> Set[str]:
    """
    Combines keywords found in existing subdomains with curated terms to
    produce candidate LABELS (not full hostnames — shuffledns prepends
    the root domain itself). Patterns generated per (keyword, term) pair:
      {keyword}-{term}, {term}-{keyword}, {keyword}{term}
    plus the bare terms themselves ({term}) since those are high-value
    guesses on their own (e.g. just "staging.example.com").
    """
    terms = terms or cfg.permutation_terms or DEFAULT_PERMUTATION_TERMS
    max_candidates = max_candidates if max_candidates is not None else cfg.permutation_max_candidates

    keywords = _extract_keywords(subdomains, cfg.domain)
    log.info(f"permutation: extracted {len(keywords)} keywords from {len(subdomains)} known subdomains")

    labels: Set[str] = set(terms)  # bare terms always included
    for kw in keywords:
        for term in terms:
            if kw == term:
                continue
            labels.add(f"{kw}-{term}")
            labels.add(f"{term}-{kw}")
            labels.add(f"{kw}{term}")
            if len(labels) >= max_candidates:
                break
        if len(labels) >= max_candidates:
            break

    if len(labels) > max_candidates:
        labels = set(sorted(labels)[:max_candidates])
        log.warning(
            f"permutation: candidate count exceeded max_candidates={max_candidates}, "
            "truncated — increase enumeration.permutation_max_candidates in "
            "settings.yaml if you want broader coverage (trades off against scan time)"
        )

    log.info(f"permutation: generated {len(labels)} candidate labels (unverified — not yet in final output)")
    return labels


def write_permutation_wordlist(cfg: Config, labels: Set[str]) -> str:
    out_path = os.path.join(cfg.raw_dir, "permutation_wordlist.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(labels)) + ("\n" if labels else ""))
    log.info(f"permutation wordlist -> {out_path} ({len(labels)} candidates, NOT yet DNS-verified)")
    return out_path
