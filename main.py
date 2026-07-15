#!/usr/bin/env python3
"""
main.py — reC0n_3ngin3 entrypoint (Phases 1-14 implemented).

Primary interface — tiered execution (Phase 14, recommended):
    python main.py --config config/settings.yaml --tier 1
    python main.py --config config/settings.yaml --tier 3 --wordlist seclists/subdomains.txt

    Tier 1: passive recon only (Phase 1) — runs regardless of authorization
    Tier 2: + live hosts + port scanning (Phase 2, 3)
    Tier 3: + crawling + JS/secret analysis (Phase 4, 5)
    Tier 4: + vuln signals, dir bruteforce, cloud probing, deep DNS (Phase 6-9)

    Each tier is cumulative and ends with Phase 10 (scoring), Phase 12
    (SQLite storage + diffing), and Phase 13 (prioritized final report) —
    see data/processed/FINAL_REPORT.txt and MASTER_REPORT.md afterward.

Secondary interface — granular phase control:
    python main.py --config config/settings.yaml --until phase5
    (runs exactly through the named phase, no scoring/storage/report step —
    use this if you're debugging one phase at a time)

Safety gate:
    Passive OSINT sources (crt.sh, VirusTotal, Chaos, GitHub, subfinder/
    assetfinder/amass-passive, ARIN/bgp.he.net, Shodan, greyhatwarfare, gf
    pattern matching) run regardless of target.authorized, since they only
    query third-party public data sets or already-collected data — no
    traffic touches the target.

    Everything from Phase 2 onward sends real traffic to the target
    (DNS resolution, HTTP probing, port scanning, crawling, fuzzing,
    active DNS/zone-transfer attempts) and refuses to run unless
    target.authorized is explicitly set to `true` in settings.yaml — i.e.
    you must affirmatively confirm you own the domain or hold written
    authorization (bug bounty scope, pentest contract, etc.) first.

    Per Phase 15: this pipeline automates data collection, filtering, and
    tagging. It deliberately does NOT automate exploitation or heavy
    fuzzing beyond curated, safety-limited defaults (e.g. nuclei is
    hard-restricted to info/low severity, non-intrusive tags; masscan and
    dir-bruteforce require explicit extra confirmation/curated target
    lists). Extend those defaults yourself, deliberately, if your
    engagement scope calls for it.
"""

import argparse
import sys

from core.config import Config
from core.orchestrator import (
    run_pipeline,
    run_phase1, run_phase2, run_phase3, run_phase4,
    run_phase5, run_phase6, run_phase7, run_phase8, run_phase9,
)
from utils.logger import setup_logging, get_logger


def parse_args():
    p = argparse.ArgumentParser(description="reC0n_3ngin3 — Phases 1-14")
    p.add_argument("--config", default="config/settings.yaml")
    p.add_argument("--wordlist", default=None, help="Wordlist for brute-force DNS expansion (Step 3)")
    p.add_argument("--dir-wordlist", default=None, help="Wordlist for ffuf directory bruteforce (Step 18)")
    p.add_argument(
        "--tier", type=int, choices=[1, 2, 3, 4], default=None,
        help="Tiered execution (Phase 14, recommended). Overrides --until if both are given.",
    )
    p.add_argument(
        "--until",
        choices=["phase1", "phase2", "phase3", "phase4", "phase5",
                 "phase6", "phase7", "phase8", "phase9"],
        default=None,
        help="Granular: run through exactly this phase, skipping scoring/storage/report.",
    )
    return p.parse_args()


def main():
    args = parse_args()
    cfg = Config(args.config)
    setup_logging(cfg.log_level, cfg.log_file)
    log = get_logger("main")

    log.info(f"Target domain: {cfg.domain}")
    log.info(f"Authorized for active steps: {cfg.authorized}")

    if not cfg.authorized:
        log.warning(
            "target.authorized is False. Passive OSINT will still run, but "
            "every active phase (2 onward) will refuse to execute until you "
            f"set it to true in {args.config}."
        )

    # Default to the tiered interface unless the caller explicitly asked
    # for granular --until control.
    if args.until is None:
        tier = args.tier or 1
        try:
            run_pipeline(cfg, tier=tier, wordlist_path=args.wordlist, dir_wordlist_path=args.dir_wordlist)
        except Exception as e:
            log.error(f"Pipeline failed: {e}")
            sys.exit(1)
        return

    # Granular mode
    try:
        p1 = run_phase1(cfg, wordlist_path=args.wordlist)

        active_phases = ("phase2", "phase3", "phase4", "phase5", "phase6", "phase7", "phase8", "phase9")
        if args.until in active_phases:
            if not cfg.authorized:
                log.error(
                    f"--until {args.until} requested but target.authorized is False. "
                    "Stopping after Phase 1 — set target.authorized: true in "
                    f"{args.config} to enable active resolution/scanning/crawling."
                )
                return
            p2 = run_phase2(cfg, p1["subdomains"])

            p3 = None
            if args.until in ("phase3", "phase4", "phase5", "phase6", "phase7", "phase8", "phase9"):
                p3 = run_phase3(cfg, p2["resolved_hosts"], p2["httpx_records"])

            p4 = None
            if args.until in ("phase4", "phase5", "phase6", "phase7", "phase8", "phase9"):
                p4 = run_phase4(cfg, p2["live_urls"])

            if args.until in ("phase5", "phase6", "phase7", "phase8", "phase9"):
                run_phase5(cfg, p4["final_urls"])

            if args.until in ("phase6", "phase7", "phase8", "phase9"):
                run_phase6(cfg, p4["final_urls"], p2["resolved_hosts"], p3["ports"])

            if args.until in ("phase7", "phase8", "phase9"):
                hv_hosts = set(p3["high_value_hosts"])
                high_priority_urls = {u for u in p2["live_urls"]
                                       if any(h in u for h in hv_hosts)} or p2["live_urls"]
                run_phase7(cfg, high_priority_urls, wordlist_path=args.dir_wordlist)

            if args.until in ("phase8", "phase9"):
                run_phase8(cfg)

            if args.until == "phase9":
                run_phase9(cfg)

    except Exception as e:
        log.error(f"Pipeline failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
