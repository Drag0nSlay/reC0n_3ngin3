#!/usr/bin/env python3
"""
main.py — reC0n_3ngin3 entrypoint.

Unified subcommand interface (recommended):
    python main.py enum -d example.com              # passive subdomain enum
    python main.py intel -d example.com             # org-wide infra intel
    python main.py subdomain -d example.com         # full Phase 1 pipeline
    python main.py resolve -d example.com           # DNS resolution + alive
    python main.py scan -d example.com              # port scan + service enum
    python main.py crawl -d example.com             # URL collection
    python main.py secrets -d example.com           # JS + secret analysis
    python main.py vuln -d example.com              # nuclei + takeover + WAF
    python main.py discover -d example.com          # dir bruteforce + screenshots
    python main.py cloud -d example.com             # bucket discovery
    python main.py dns -d example.com               # dnsrecon + amass active
    python main.py full -d example.com              # run everything (tier 4)

    Each subcommand automatically runs the equivalent operation across
    ALL installed recon tools — no need to remember individual tool syntax.

Legacy tiered interface (still fully supported):
    python main.py --config config/settings.yaml --tier 1
    python main.py --config config/settings.yaml --tier 3 --wordlist seclists/subdomains.txt

    Tier 1: passive recon only (Phase 1) — runs regardless of authorization
    Tier 2: + live hosts + port scanning (Phase 2, 3)
    Tier 3: + crawling + JS/secret analysis (Phase 4, 5)
    Tier 4: + vuln signals, dir bruteforce, cloud probing, deep DNS (Phase 6-9)

    Each tier is cumulative and ends with Phase 10 (scoring), Phase 12
    (SQLite storage + diffing), and Phase 13 (prioritized final report) —
    see data/processed/FINAL_REPORT.txt and MASTER_REPORT.md afterward.

Legacy granular phase control:
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

import sys

from core.cli import build_parser, dispatch, cmd_pipeline


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ---- Dispatch logic ----
    # Case 1: explicit subcommand given (enum, intel, subdomain, etc.)
    if args.subcommand:
        dispatch(args)
        return

    # Case 2: no subcommand, but legacy --tier or --until flags present
    #         → route to the pipeline handler for backward compatibility
    if args.tier is not None or args.until is not None:
        # Ensure pipeline handler has all the attributes it expects
        if not hasattr(args, "dir_wordlist"):
            args.dir_wordlist = getattr(args, "dir_wordlist", None)
        cmd_pipeline(args)
        return

    # Case 3: nothing at all → show help
    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
