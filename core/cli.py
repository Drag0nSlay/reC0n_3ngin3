"""
core/cli.py

Unified subcommand dispatcher for reC0n_3ngin3.

Maps user-facing subcommands to the correct orchestrator / module
functions so that one `main.py <subcommand>` triggers the equivalent
operations across ALL installed external recon tools.

Subcommands
-----------
  enum        Passive subdomain enumeration (subfinder + assetfinder +
              amass passive + crt.sh + VT + Chaos + GitHub search)
  intel       Organization-wide infrastructure intel (amass intel -org +
              ARIN WHOIS + bgp.he.net + asnmap + Shodan)
  subdomain   Full Phase 1 pipeline (enum + intel + brute + permutation +
              recursive) → final_subdomains.txt
  resolve     DNS resolution + alive detection (dnsx + httpx)
  scan        Port scanning + service enumeration (naabu + rustscan + nmap)
  crawl       URL collection (waybackurls + gau + katana)
  secrets     JS + secret analysis (LinkFinder + SecretFinder + GitHub leaks)
  vuln        Vulnerability signals (nuclei + subzy + wafw00f + gf)
  discover    Content discovery (ffuf/dirsearch + EyeWitness)
  cloud       Cloud recon (S3Scanner + lazys3 + greyhatwarfare)
  dns         Deep/active DNS (dnsrecon + amass active)
  full        Run everything (equivalent to --tier 4)

Backward compatibility: if no subcommand is given but --tier / --until
flags are present, falls through to the legacy pipeline behavior.
"""

from __future__ import annotations
import argparse
import os
import sys
from typing import Optional

from core.config import Config
from utils.logger import setup_logging, get_logger


# ---------------------------------------------------------------------------
# Helper: load config with optional domain override
# ---------------------------------------------------------------------------
def _load_config(args) -> Config:
    """Load Config from the --config path, optionally overriding the domain."""
    cfg = Config(args.config)
    if hasattr(args, "domain") and args.domain:
        cfg._raw["target"]["domain"] = args.domain
    return cfg


def _setup(args):
    """Common setup: load config + start logging. Returns (cfg, log)."""
    cfg = _load_config(args)
    setup_logging(cfg.log_level, cfg.log_file)
    log = get_logger("cli")
    log.info(f"Target domain: {cfg.domain}")
    log.info(f"Authorized for active steps: {cfg.authorized}")
    return cfg, log


def _require_auth(cfg, log, subcommand: str) -> bool:
    """Gate active subcommands on cfg.authorized. Returns True if OK."""
    if not cfg.authorized:
        log.error(
            f"'{subcommand}' sends active traffic to the target. "
            f"target.authorized is False — set it to true in your config "
            f"once you have confirmed you own or are authorized to test "
            f"this domain."
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_enum(args):
    """
    Passive subdomain enumeration — runs ALL passive sources concurrently:
      subfinder, assetfinder, amass enum -passive, crt.sh, VirusTotal,
      Chaos, GitHub code search.
    No traffic to the target. No authorization required.
    """
    cfg, log = _setup(args)
    os.makedirs(cfg.raw_dir, exist_ok=True)
    os.makedirs(cfg.processed_dir, exist_ok=True)

    from modules.enum import passive_sources

    log.info("=== ENUM: Passive subdomain enumeration (all sources) ===")
    domains = passive_sources.run_all_passive(cfg)
    log.info(f"=== ENUM COMPLETE: {len(domains)} unique subdomains found ===")
    return {"subdomains": domains}


def cmd_intel(args):
    """
    Organization-wide infrastructure intel — discovers ASNs, netblocks,
    and WHOIS data that may reveal other root domains the org owns:
      amass intel -org, ARIN RDAP, bgp.he.net, asnmap.
    Plus Shodan host lookup if IPs are available.
    No direct traffic to the target — queries third-party registries.
    """
    cfg, log = _setup(args)
    os.makedirs(cfg.raw_dir, exist_ok=True)
    os.makedirs(cfg.processed_dir, exist_ok=True)

    from modules.enum import passive_sources, asn_ip

    log.info("=== INTEL: Organization-wide infrastructure intelligence ===")

    # amass intel -org (org-wide ASN/netblock/whois discovery)
    log.info("Step 1: amass intel -org (organization-level discovery)")
    intel_data = passive_sources.amass_intel_org(cfg)

    # ASN + IP mapping (ARIN, bgp.he.net, asnmap, mapcidr)
    log.info("Step 2: ASN + IP mapping (asnmap, ARIN RDAP, bgp.he.net)")
    asn_data = asn_ip.run_asn_ip_stage(cfg)

    # Shodan (if we have IPs and a key)
    shodan_results = []
    ips = sorted(asn_data.get("ips", set()))
    if ips:
        try:
            from modules.intel import shodan_intel
            log.info(f"Step 3: Shodan host lookup ({len(ips)} IPs)")
            shodan_results = shodan_intel.shodan_host_lookup(cfg, ips[:50])
        except Exception as e:
            log.warning(f"Shodan lookup failed: {e}")

    log.info("=== INTEL COMPLETE ===")
    log.info(f"  amass intel lines: {len(intel_data)}")
    log.info(f"  ASN handles: {len(asn_data.get('asn', []))}")
    log.info(f"  CIDR ranges: {len(asn_data.get('cidr', []))}")
    log.info(f"  IPs expanded: {len(asn_data.get('ips', []))}")
    log.info(f"  Shodan results: {len(shodan_results)}")

    return {"intel": intel_data, "asn_ip": asn_data, "shodan": shodan_results}


def cmd_subdomain(args):
    """
    Full Phase 1 subdomain pipeline:
      enum (all passive sources) + intel (ASN/IP) + brute-force DNS +
      permutation expansion + recursive enumeration → final_subdomains.txt
    """
    cfg, log = _setup(args)

    from core.orchestrator import run_phase1

    log.info("=== SUBDOMAIN: Full subdomain discovery pipeline ===")
    result = run_phase1(cfg, wordlist_path=getattr(args, "wordlist", None))
    log.info(f"=== SUBDOMAIN COMPLETE: {len(result['subdomains'])} final subdomains ===")
    return result


def cmd_resolve(args):
    """
    DNS resolution + alive detection:
      dnsx (A, AAAA, CNAME, MX, NS) + httpx (status, title, tech, favicon).
    Requires prior subdomain data in data/processed/<domain>/final_subdomains.txt,
    or run 'subdomain' first.
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "resolve"):
        return {}

    from core.orchestrator import run_phase2
    subdomains = _load_prior_subdomains(cfg, log)
    if not subdomains:
        return {}

    log.info(f"=== RESOLVE: DNS resolution + alive detection ({len(subdomains)} inputs) ===")
    result = run_phase2(cfg, subdomains)
    log.info(f"=== RESOLVE COMPLETE: {len(result['live_urls'])} live hosts ===")
    return result


def cmd_scan(args):
    """
    Port scanning + service enumeration:
      naabu (fast top-N ports) + rustscan (supplement) + nmap -sV -sC
      (high-value hosts only).
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "scan"):
        return {}

    # Need resolved hosts — try loading from prior run
    subdomains = _load_prior_subdomains(cfg, log)
    if not subdomains:
        return {}

    from core.orchestrator import run_phase2, run_phase3

    log.info("=== SCAN: Running resolution then port scanning ===")
    p2 = run_phase2(cfg, subdomains)
    if not p2["resolved_hosts"]:
        log.warning("No resolved hosts — nothing to scan.")
        return {}

    result = run_phase3(cfg, p2["resolved_hosts"], p2["httpx_records"])
    log.info(f"=== SCAN COMPLETE: {len(result['ports'])} open host:port pairs ===")
    return result


def cmd_crawl(args):
    """
    URL collection:
      waybackurls + gau (historical) + katana (live crawl).
    ACTIVE — requires authorization (katana sends traffic).
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "crawl"):
        return {}

    # Need live URLs — try loading from prior run
    live_urls = _load_prior_live_urls(cfg, log)
    if not live_urls:
        log.warning("No live URLs found. Run 'resolve' first, or using domain as seed.")
        live_urls = {f"https://{cfg.domain}"}

    from core.orchestrator import run_phase4

    log.info(f"=== CRAWL: URL collection ({len(live_urls)} live hosts) ===")
    result = run_phase4(cfg, live_urls)
    log.info(f"=== CRAWL COMPLETE: {len(result['final_urls'])} total URLs ===")
    return result


def cmd_secrets(args):
    """
    JS + secret analysis:
      LinkFinder (endpoints) + SecretFinder (secrets in JS) + mantra +
      trufflehog / gitgraber / gitdorker (GitHub leak detection).
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "secrets"):
        return {}

    final_urls = _load_prior_final_urls(cfg, log)
    if not final_urls:
        log.warning("No URLs found. Run 'crawl' first, or using domain as seed.")
        final_urls = {f"https://{cfg.domain}"}

    from core.orchestrator import run_phase5

    log.info(f"=== SECRETS: JS + secret analysis ({len(final_urls)} URLs) ===")
    result = run_phase5(cfg, final_urls)
    log.info(f"=== SECRETS COMPLETE ===")
    return result


def cmd_vuln(args):
    """
    Vulnerability signal collection (safe/passive-leaning):
      nuclei (info+low severity, non-intrusive tags) + subzy (takeover) +
      wafw00f (WAF detection) + gf (pattern matching).
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "vuln"):
        return {}

    final_urls = _load_prior_final_urls(cfg, log)
    resolved_hosts = _load_prior_subdomains(cfg, log)
    if not final_urls:
        log.warning("No URLs found. Run 'crawl' first.")
        return {}

    # For port_pairs, try to load from processed data
    port_pairs = set()
    ports_file = os.path.join(cfg.processed_dir, "open_ports.txt")
    if os.path.exists(ports_file):
        with open(ports_file, "r") as f:
            port_pairs = {l.strip() for l in f if l.strip()}

    from core.orchestrator import run_phase6

    log.info(f"=== VULN: Vulnerability signal collection ({len(final_urls)} URLs) ===")
    result = run_phase6(cfg, final_urls, resolved_hosts, port_pairs)
    log.info(f"=== VULN COMPLETE ===")
    return result


def cmd_discover(args):
    """
    Content discovery:
      ffuf / dirsearch (directory bruteforce) + EyeWitness (screenshots).
    Only runs against high-priority hosts.
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "discover"):
        return {}

    live_urls = _load_prior_live_urls(cfg, log)
    if not live_urls:
        log.warning("No live URLs found. Run 'resolve' first.")
        return {}

    from core.orchestrator import run_phase7

    log.info(f"=== DISCOVER: Content discovery ({len(live_urls)} hosts) ===")
    result = run_phase7(cfg, live_urls, wordlist_path=getattr(args, "dir_wordlist", None))
    log.info(f"=== DISCOVER COMPLETE ===")
    return result


def cmd_cloud(args):
    """
    Cloud recon:
      greyhatwarfare API + aws s3 ls + lazys3 + S3Scanner.
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "cloud"):
        return {}

    from core.orchestrator import run_phase8

    log.info("=== CLOUD: Cloud recon (bucket discovery) ===")
    result = run_phase8(cfg)
    log.info(f"=== CLOUD COMPLETE ===")
    return result


def cmd_dns(args):
    """
    Deep/active DNS enumeration:
      dnsrecon -d <domain> -a (zone transfer attempts) +
      amass enum -active -d <domain>.
    Aggressive — sends real DNS traffic to the target's nameservers.
    ACTIVE — requires authorization.
    """
    cfg, log = _setup(args)
    if not _require_auth(cfg, log, "dns"):
        return {}

    from core.orchestrator import run_phase9

    log.info("=== DNS: Deep/active DNS enumeration ===")
    result = run_phase9(cfg)
    log.info(f"=== DNS COMPLETE ===")
    return result


def cmd_full(args):
    """
    Full pipeline — equivalent to --tier 4. Runs everything:
      enum → intel → subdomain → resolve → scan → crawl → secrets →
      vuln → discover → cloud → dns → scoring → storage → report.
    """
    cfg, log = _setup(args)

    from core.orchestrator import run_pipeline

    log.info("=== FULL: Running complete pipeline (all phases) ===")
    result = run_pipeline(
        cfg,
        tier=4,
        wordlist_path=getattr(args, "wordlist", None),
        dir_wordlist_path=getattr(args, "dir_wordlist", None),
    )
    log.info(f"=== FULL PIPELINE COMPLETE ===")
    return result


def cmd_pipeline(args):
    """
    Legacy interface — backward-compatible --tier / --until execution.
    Identical to the old main.py behavior.
    """
    cfg, log = _setup(args)

    from core.orchestrator import run_pipeline, run_phase1, run_phase2, run_phase3
    from core.orchestrator import run_phase4, run_phase5, run_phase6, run_phase7
    from core.orchestrator import run_phase8, run_phase9

    if not cfg.authorized:
        log.warning(
            "target.authorized is False. Passive OSINT will still run, but "
            "every active phase (2 onward) will refuse to execute until you "
            f"set it to true in {args.config}."
        )

    if args.until is None:
        tier = args.tier or 1
        try:
            run_pipeline(cfg, tier=tier, wordlist_path=args.wordlist, dir_wordlist_path=args.dir_wordlist)
        except Exception as e:
            log.error(f"Pipeline failed: {e}")
            sys.exit(1)
        return

    # Granular --until mode
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


# ---------------------------------------------------------------------------
# Data loaders — load artifacts from prior subcommand runs
# ---------------------------------------------------------------------------

def _load_prior_subdomains(cfg: Config, log) -> set:
    """Load final_subdomains.txt from a prior 'subdomain' or 'enum' run."""
    path = os.path.join(cfg.processed_dir, "final_subdomains.txt")
    if not os.path.exists(path):
        # Fallback to raw merged output
        path = os.path.join(cfg.raw_dir, "all_subdomains_raw.txt")

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            subs = {l.strip() for l in f if l.strip()}
        log.info(f"Loaded {len(subs)} subdomains from {path}")
        return subs

    log.error(
        f"No subdomain data found at {cfg.processed_dir}/final_subdomains.txt. "
        "Run 'python main.py subdomain' or 'python main.py enum' first."
    )
    return set()


def _load_prior_live_urls(cfg: Config, log) -> set:
    """Load live URLs from a prior 'resolve' run."""
    path = os.path.join(cfg.processed_dir, "live_urls.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            urls = {l.strip() for l in f if l.strip()}
        log.info(f"Loaded {len(urls)} live URLs from {path}")
        return urls
    return set()


def _load_prior_final_urls(cfg: Config, log) -> set:
    """Load merged final URLs from a prior 'crawl' run."""
    path = os.path.join(cfg.processed_dir, "final_urls.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            urls = {l.strip() for l in f if l.strip()}
        log.info(f"Loaded {len(urls)} final URLs from {path}")
        return urls
    # Fallback to live_urls
    return _load_prior_live_urls(cfg, log)


# ---------------------------------------------------------------------------
# Argparse setup
# ---------------------------------------------------------------------------

SUBCOMMAND_MAP = {
    "enum":      cmd_enum,
    "intel":     cmd_intel,
    "subdomain": cmd_subdomain,
    "resolve":   cmd_resolve,
    "scan":      cmd_scan,
    "crawl":     cmd_crawl,
    "secrets":   cmd_secrets,
    "vuln":      cmd_vuln,
    "discover":  cmd_discover,
    "cloud":     cmd_cloud,
    "dns":       cmd_dns,
    "full":      cmd_full,
    "pipeline":  cmd_pipeline,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the unified argparse parser with subcommands."""
    # ---- top-level parser ----
    p = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "reC0n_3ngin3 — unified reconnaissance pipeline.\n\n"
            "Use subcommands to run specific recon categories, or\n"
            "use --tier/--until for the legacy pipeline interface."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py enum -d example.com          # passive subdomain enumeration\n"
            "  python main.py intel -d example.com         # org-wide infrastructure intel\n"
            "  python main.py subdomain -d example.com     # full subdomain pipeline\n"
            "  python main.py full -d example.com          # run everything\n"
            "  python main.py --tier 1                     # legacy tier-based mode\n"
            "  python main.py --until phase3               # legacy phase-based mode\n"
        ),
    )

    # Top-level flags for backward compatibility (legacy pipeline mode)
    p.add_argument("--config", "-c", default="config/settings.yaml",
                   help="Path to settings.yaml config file")
    p.add_argument("--tier", type=int, choices=[1, 2, 3, 4], default=None,
                   help="(Legacy) Tiered execution — runs through the selected tier")
    p.add_argument("--until",
                   choices=["phase1", "phase2", "phase3", "phase4", "phase5",
                            "phase6", "phase7", "phase8", "phase9"],
                   default=None,
                   help="(Legacy) Run through exactly this phase")
    p.add_argument("--wordlist", default=None,
                   help="Wordlist for brute-force DNS expansion")
    p.add_argument("--dir-wordlist", default=None,
                   help="Wordlist for directory bruteforce (ffuf/dirsearch)")

    # ---- subcommands ----
    subs = p.add_subparsers(dest="subcommand", title="subcommands",
                            description="Run a specific recon category across all tools")

    def _add_common(sub):
        """Add common flags to every subcommand."""
        sub.add_argument("-d", "--domain", default=None,
                         help="Target domain (overrides settings.yaml)")
        sub.add_argument("-c", "--config", default="config/settings.yaml",
                         help="Path to settings.yaml config file")

    # enum
    s = subs.add_parser("enum",
        help="Passive subdomain enumeration (subfinder, assetfinder, amass, crt.sh, VT, Chaos, GitHub)",
        description="Run ALL passive subdomain enumeration sources concurrently. "
                    "No traffic to the target — queries third-party APIs and data sets only.")
    _add_common(s)

    # intel
    s = subs.add_parser("intel",
        help="Org-wide infrastructure intel (amass intel, ARIN, bgp.he.net, asnmap, Shodan)",
        description="Discover ASNs, netblocks, WHOIS data, and infrastructure the org owns. "
                    "May reveal other root domains. Queries third-party registries only.")
    _add_common(s)

    # subdomain
    s = subs.add_parser("subdomain",
        help="Full subdomain pipeline (enum + intel + brute + permutation + recursive)",
        description="Complete Phase 1: passive enum → ASN/IP mapping → brute-force DNS → "
                    "permutation expansion → recursive enumeration → final_subdomains.txt")
    _add_common(s)
    s.add_argument("--wordlist", "-w", default=None,
                   help="Wordlist for brute-force DNS expansion (shuffledns)")

    # resolve
    s = subs.add_parser("resolve",
        help="DNS resolution + alive detection (dnsx + httpx)",
        description="Resolve discovered subdomains via dnsx, then probe for live hosts via httpx. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # scan
    s = subs.add_parser("scan",
        help="Port scanning + service enumeration (naabu + rustscan + nmap)",
        description="Fast port scan (naabu/rustscan) then targeted nmap -sV -sC on high-value hosts. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # crawl
    s = subs.add_parser("crawl",
        help="URL collection (waybackurls + gau + katana)",
        description="Collect URLs from historical archives (waybackurls, gau) and live crawling (katana). "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # secrets
    s = subs.add_parser("secrets",
        help="JS + secret analysis (LinkFinder, SecretFinder, GitHub leaks)",
        description="Extract endpoints and secrets from JS files, scan for GitHub leaks. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # vuln
    s = subs.add_parser("vuln",
        help="Vulnerability signals (nuclei + subzy + wafw00f + gf)",
        description="Safe vulnerability signal collection: nuclei (info/low only), subdomain takeover, "
                    "WAF detection, gf pattern matching. ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # discover
    s = subs.add_parser("discover",
        help="Content discovery (ffuf/dirsearch + EyeWitness screenshots)",
        description="Directory bruteforce on high-priority hosts + screenshot capture. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)
    s.add_argument("--dir-wordlist", default=None,
                   help="Wordlist for directory bruteforce (ffuf/dirsearch)")

    # cloud
    s = subs.add_parser("cloud",
        help="Cloud recon (S3Scanner, lazys3, greyhatwarfare)",
        description="Bucket discovery via greyhatwarfare API, aws s3 ls, lazys3, S3Scanner. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # dns
    s = subs.add_parser("dns",
        help="Deep/active DNS (dnsrecon + amass active)",
        description="Aggressive DNS enumeration: zone transfer attempts (dnsrecon -a) + "
                    "amass enum -active. Sends real DNS traffic to the target's nameservers. "
                    "ACTIVE — requires target.authorized: true.")
    _add_common(s)

    # full
    s = subs.add_parser("full",
        help="Run everything — equivalent to --tier 4",
        description="Complete pipeline: all phases, all tools. Ends with scoring, SQLite storage, "
                    "and a prioritized final report.")
    _add_common(s)
    s.add_argument("--wordlist", "-w", default=None,
                   help="Wordlist for brute-force DNS expansion")
    s.add_argument("--dir-wordlist", default=None,
                   help="Wordlist for directory bruteforce")

    # pipeline (explicit legacy mode)
    s = subs.add_parser("pipeline",
        help="(Legacy) Tier/phase-based pipeline — backward-compatible interface",
        description="Run the tiered pipeline exactly as the original --tier / --until interface.")
    _add_common(s)
    s.add_argument("--tier", type=int, choices=[1, 2, 3, 4], default=None,
                   help="Tiered execution — runs through the selected tier")
    s.add_argument("--until",
                   choices=["phase1", "phase2", "phase3", "phase4", "phase5",
                            "phase6", "phase7", "phase8", "phase9"],
                   default=None,
                   help="Run through exactly this phase")
    s.add_argument("--wordlist", "-w", default=None,
                   help="Wordlist for brute-force DNS expansion")
    s.add_argument("--dir-wordlist", default=None,
                   help="Wordlist for directory bruteforce")

    return p


def dispatch(args: argparse.Namespace):
    """Route to the correct handler based on subcommand."""
    handler = SUBCOMMAND_MAP.get(args.subcommand)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            log = get_logger("cli")
            log.warning("Interrupted by user (Ctrl+C)")
            sys.exit(130)
        except Exception as e:
            log = get_logger("cli")
            log.error(f"Command '{args.subcommand}' failed: {e}")
            sys.exit(1)
    else:
        # Should not happen if argparse is configured correctly
        print(f"Unknown subcommand: {args.subcommand}", file=sys.stderr)
        sys.exit(1)
