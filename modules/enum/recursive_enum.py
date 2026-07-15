"""
modules/enum/recursive_enum.py

Extends Phase 1 with recursive passive enumeration: for a *curated
subset* of already-discovered subdomains that look like they might have
their own sub-tree (internal.example.com, corp.example.com, etc.), re-run
the same trusted passive sources against them as new sub-roots to find
*.internal.example.com style nested assets.

Design constraints (deliberate, to avoid rate-limit exhaustion and
false-positive/duplicate blowup):
  - Only recurses into subdomains matching a curated keyword list —
    never all discovered subdomains (5000+ subdomains x 3 API calls
    each would blow through crt.sh/VT/Chaos rate limits immediately).
  - Depth is hard-capped at 1 — results of recursion are never
    themselves recursed into. No exponential blowup possible.
  - Uses only FAST_SOURCES (crt.sh, VirusTotal, Chaos) — no CLI
    binaries like subfinder/amass, since those can take minutes per
    invocation and recursion may run N times.
  - Max sub-roots capped via config (enumeration.recursion_max_subroots).
  - All results pass through the same dedupe.py normalization as
    primary Phase 1 output — same trust level, no separate "unverified"
    flag needed here (unlike permutation.py's DNS-unconfirmed guesses).

Output: data/raw/recursive_<subroot>_all_subdomains_raw.txt (per sub-root)
        merged into the Phase 1 final subdomain set by the orchestrator
"""

from __future__ import annotations
import re
from typing import List, Set

from utils.logger import get_logger
from core.config import Config
from modules.enum import passive_sources

log = get_logger("enum.recursive")

DEFAULT_RECURSION_KEYWORDS = [
    "internal", "corp", "dev", "staging", "vpn", "admin",
    "cloud", "aws", "azure", "network", "office", "test",
]


def select_recursion_roots(
    subdomains: Set[str],
    root_domain: str,
    keywords: List[str] | None = None,
    max_subroots: int = 10,
) -> List[str]:
    """
    Picks a bounded, curated subset of discovered subdomains worth
    recursing into. A subdomain qualifies if its leftmost label matches
    a recursion keyword AND it isn't just the apex/root domain itself.
    """
    keywords = keywords or DEFAULT_RECURSION_KEYWORDS
    pattern = re.compile(r"(?:^|[.-])(" + "|".join(re.escape(k) for k in keywords) + r")(?:[.-]|$)", re.IGNORECASE)

    candidates = set()
    for sub in subdomains:
        if sub == root_domain:
            continue
        if pattern.search(sub):
            candidates.add(sub)

    result = sorted(candidates)[:max_subroots]
    log.info(
        f"recursion candidates: {len(candidates)} matched keywords, "
        f"capped to {len(result)} (max_subroots={max_subroots})"
    )
    return result


def run_recursive_enumeration(
    cfg: Config,
    subdomains: Set[str],
    keywords: List[str] | None = None,
    max_subroots: int | None = None,
) -> Set[str]:
    """
    Phase 1 extension: recurse one level into curated sub-roots using
    only fast passive API sources. Returns the NEW subdomains found
    (already deduped against the input set).
    """
    max_subroots = max_subroots if max_subroots is not None else cfg.recursion_max_subroots
    keywords = keywords or cfg.recursion_keywords or DEFAULT_RECURSION_KEYWORDS

    roots = select_recursion_roots(subdomains, cfg.domain, keywords, max_subroots)
    if not roots:
        log.info("recursive enumeration: no sub-roots matched, skipping")
        return set()

    all_new: Set[str] = set()
    for i, sub_root in enumerate(roots, 1):
        log.info(f"recursive enumeration [{i}/{len(roots)}]: {sub_root}")
        prefix = f"recursive_{sub_root.replace('.', '_')}_"
        found = passive_sources.run_all_passive(
            cfg,
            domain=sub_root,
            prefix=prefix,
            sources=passive_sources.FAST_SOURCES,
        )
        # Only genuinely new discoveries count — dedupe against what we
        # already had from the primary pass (and across sub-roots too).
        new_here = (found | {sub_root}) - subdomains - all_new
        if new_here:
            log.info(f"  -> {len(new_here)} new subdomains under {sub_root}")
        all_new |= new_here

    log.info(f"recursive enumeration total: {len(all_new)} new subdomains across {len(roots)} sub-roots")
    return all_new
