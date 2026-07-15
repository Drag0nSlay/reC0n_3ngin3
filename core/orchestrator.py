"""
core/orchestrator.py

Phase 1 orchestrator: Target Enumeration Engine.
Runs steps 1-3 in order (passive-first, per core principle #1),
persisting intermediate artifacts at every stage (principle #3) so any
step can be re-run independently without redoing earlier work.
"""

from __future__ import annotations
import os
from core.config import Config
from core.storage import Storage
from utils.logger import setup_logging, get_logger
from modules.enum import passive_sources, asn_ip, brute, deep_dns, recursive_enum, permutation
from modules.resolve import dnsx, httpx_probe
from modules.scan import ports, services, nuclei_scan, takeover
from modules.crawl import historical_urls, live_crawl
from modules.secrets import js_extract, endpoint_secrets, github_leakage
from modules.intel import shodan_intel, waf_detect, gf_patterns, scoring
from modules.content import dir_bruteforce, screenshots
from modules.cloud import bucket_discovery
from output import report as report_mod

log = get_logger("orchestrator")

# --------------------------------------------------------------------------
# Phase 14 — Execution Strategy: tiers, cumulative (each tier implies all
# lower tiers ran first). Don't run everything blindly — pick the tier that
# matches how much you actually need this pass.
#
#   Tier 1: passive recon only            -> Phase 1
#   Tier 2: + live hosts + port scanning   -> Phase 2, 3
#   Tier 3: + crawling + JS/secret analysis -> Phase 4, 5
#   Tier 4: + fuzzing/brute + everything else aggressive
#           (vuln signals, dir bruteforce, cloud probing, deep DNS)
#                                           -> Phase 6, 7, 8, 9
# --------------------------------------------------------------------------
TIER_PHASES = {
    1: ["phase1"],
    2: ["phase1", "phase2", "phase3"],
    3: ["phase1", "phase2", "phase3", "phase4", "phase5"],
    4: ["phase1", "phase2", "phase3", "phase4", "phase5", "phase6", "phase7", "phase8", "phase9"],
}


def run_phase1(cfg: Config, wordlist_path: str | None = None, enable_permutation: bool = True,
               enable_recursion: bool = True) -> dict:
    os.makedirs(cfg.raw_dir, exist_ok=True)
    os.makedirs(cfg.processed_dir, exist_ok=True)

    log.info(f"=== PHASE 1: TARGET ENUMERATION — {cfg.domain} ===")

    # Step 1 — passive base assets (safe to run regardless of authorization,
    # these are all public third-party data sources, no packets to target)
    log.info("Step 1/3: passive base asset collection")
    base_domains = passive_sources.run_all_passive(cfg)

    # Step 1a — org-wide intel (supplementary, NOT merged into base_domains —
    # amass intel -org surfaces ASNs/netblocks/whois hits, not confirmed
    # subdomains, so it's written to its own file for manual review/pivoting)
    log.info("Step 1a: organization-wide ASN/netblock intel (amass intel -org)")
    passive_sources.amass_intel_org(cfg)

    # Step 1b — recursive enumeration: re-run fast passive sources against
    # a curated subset of already-discovered subdomains that look like
    # they might have their own sub-tree. Same trust level as base_domains
    # (still passive lookups, just a different root) — merged directly,
    # no DNS verification needed since no guessing is involved here.
    recursive_domains: set = set()
    if enable_recursion:
        log.info("Step 1b: recursive enumeration on curated sub-roots")
        recursive_domains = recursive_enum.run_recursive_enumeration(cfg, base_domains)
        base_domains = base_domains | recursive_domains

    # Step 2 — ASN + IP mapping (also passive/public registry data)
    log.info("Step 2/3: ASN + IP mapping")
    asn_ip_data = asn_ip.run_asn_ip_stage(cfg)

    # Step 3 — brute expansion (semi-active: DNS queries against target's
    # nameservers). Gated on cfg.authorized inside brute.shuffledns_brute.
    # Permutation candidates are merged into the same wordlist so they go
    # through the exact same DNS-verification step as a user-supplied
    # wordlist — no unverified guesses ever reach final_subdomains.txt.
    permutation_wordlist_path = None
    if enable_permutation:
        log.info("Step 3a: generating permutation candidates from known subdomain keywords")
        labels = permutation.generate_permutation_labels(cfg, base_domains)
        permutation_wordlist_path = permutation.write_permutation_wordlist(cfg, labels)

    brute_domains = set()
    combined_wordlist = brute.combine_wordlists(cfg, wordlist_path, permutation_wordlist_path)
    if combined_wordlist:
        log.info("Step 3b: brute-force DNS expansion (user wordlist + permutation candidates)")
        brute_domains = brute.shuffledns_brute(cfg, combined_wordlist)
    else:
        log.info("Step 3b: skipped (no --wordlist provided and permutation disabled/empty)")

    final = brute.merge_final(cfg, base_domains, brute_domains)

    log.info("=== PHASE 1 COMPLETE ===")
    log.info(f"  base (passive):      {len(base_domains) - len(recursive_domains)}")
    log.info(f"  recursive (passive): {len(recursive_domains)}")
    log.info(f"  brute (active DNS, incl. permutation hits): {len(brute_domains)}")
    log.info(f"  ASN handles:        {len(asn_ip_data.get('asn', []))}")
    log.info(f"  CIDR ranges:        {len(asn_ip_data.get('cidr', []))}")
    log.info(f"  IPs expanded:       {len(asn_ip_data.get('ips', []))}")
    log.info(f"  FINAL subdomains:   {len(final)}  -> {cfg.processed_dir}/final_subdomains.txt")

    return {
        "subdomains": final,
        "asn_ip": asn_ip_data,
    }


def run_phase2(cfg: Config, subdomains: set) -> dict:
    """Phase 2: Resolution Layer — DNS resolution then alive detection."""
    log.info(f"=== PHASE 2: RESOLUTION LAYER ({len(subdomains)} input domains) ===")

    log.info("Step 4/5: DNS resolution (dnsx)")
    resolve_result = dnsx.resolve_domains(cfg, subdomains)
    hosts = resolve_result["hosts"]

    log.info("Step 5/5: alive detection (httpx)")
    probe_result = httpx_probe.probe_alive(cfg, hosts)

    log.info("=== PHASE 2 COMPLETE ===")
    log.info(f"  resolved hosts: {len(hosts)}")
    log.info(f"  live hosts:     {len(probe_result['live_urls'])}")

    return {
        "resolved_hosts": hosts,
        "live_urls": probe_result["live_urls"],
        "httpx_records": probe_result["records"],
    }


def run_phase3(cfg: Config, resolved_hosts: set, httpx_records: list) -> dict:
    """Phase 3: Network Scanning — port scan cascade, then targeted service enum."""
    log.info(f"=== PHASE 3: NETWORK SCANNING ({len(resolved_hosts)} input hosts) ===")

    log.info("Step 6/7: port scanning (naabu -> rustscan)")
    port_pairs = ports.run_port_scan_stage(cfg, resolved_hosts)

    log.info("Step 7/7: service enumeration (nmap -sV -sC, high-value hosts only)")
    high_value = services.select_high_value_hosts(
        port_pairs, httpx_records, max_hosts=cfg.nmap_max_high_value_hosts
    )
    service_result = services.nmap_service_scan(cfg, high_value)

    log.info("=== PHASE 3 COMPLETE ===")
    log.info(f"  open host:port pairs: {len(port_pairs)}")
    log.info(f"  high-value hosts scanned: {len(service_result['hosts_scanned'])}")

    return {
        "ports": port_pairs,
        "high_value_hosts": high_value,
        "nmap_text": service_result["text"],
    }


def run_phase4(cfg: Config, live_urls: set) -> dict:
    """Phase 4: Crawling + Endpoint Discovery."""
    log.info(f"=== PHASE 4: CRAWLING + ENDPOINT DISCOVERY ({len(live_urls)} live hosts) ===")

    log.info("Step 8/9: historical URLs (waybackurls + gau)")
    historical = historical_urls.collect_historical_urls(cfg)

    log.info("Step 9/9: live crawling (katana)")
    live_found = live_crawl.katana_crawl(cfg, live_urls)

    final = live_crawl.merge_final_urls(cfg, historical, live_found)

    log.info("=== PHASE 4 COMPLETE ===")
    log.info(f"  historical URLs: {len(historical)}")
    log.info(f"  live-crawled URLs: {len(live_found)}")
    log.info(f"  FINAL URLs: {len(final)}")

    return {"final_urls": final}


def run_phase5(cfg: Config, final_urls: set) -> dict:
    """Phase 5: JS + Secret Analysis."""
    log.info(f"=== PHASE 5: JS + SECRET ANALYSIS ({len(final_urls)} URLs) ===")

    log.info("Step 10: JS extraction")
    js_files = js_extract.extract_js_files(cfg, final_urls)

    log.info("Step 11: endpoint + secret discovery")
    es_result = endpoint_secrets.analyze_js_files(cfg, js_files)

    log.info("Step 12: GitHub leakage")
    github_findings = github_leakage.run_github_leakage_stage(cfg)

    log.info("=== PHASE 5 COMPLETE ===")
    log.info(f"  JS files: {len(js_files)}")
    log.info(f"  endpoints: {len(es_result['endpoints'])}")
    log.info(f"  secrets (redacted): {len(es_result['secrets'])}")
    log.info(f"  GitHub findings: {len(github_findings)}")

    return {
        "js_files": js_files,
        "endpoints": es_result["endpoints"],
        "secrets": es_result["secrets"],
        "github_findings": github_findings,
    }


def run_phase6(cfg: Config, final_urls: set, resolved_hosts: set, port_pairs: set) -> dict:
    """Phase 6: Vulnerability Signal Collection (safe templates / passive-leaning checks)."""
    log.info("=== PHASE 6: VULNERABILITY SIGNAL COLLECTION (SAFE) ===")

    ips = sorted({p.split(":")[0] for p in port_pairs if ":" in p})

    log.info("Step 13: Shodan service intelligence")
    shodan_results = shodan_intel.shodan_host_lookup(cfg, ips)

    log.info("Step 14: WAF detection (wafw00f)")
    waf_results = waf_detect.wafw00f_scan(cfg, final_urls)

    log.info("Step 15: nuclei template scanning (safe templates only)")
    nuclei_results = nuclei_scan.nuclei_safe_scan(cfg, final_urls)

    log.info("Step 16: gf pattern matching")
    gf_results = gf_patterns.gf_scan(cfg, final_urls)

    log.info("Step 17: subdomain takeover (subzy)")
    takeover_results = takeover.subzy_scan(cfg, resolved_hosts)

    log.info("=== PHASE 6 COMPLETE ===")
    log.info(f"  Shodan hosts: {len(shodan_results)}")
    log.info(f"  WAF results: {len(waf_results)}")
    log.info(f"  nuclei findings: {len(nuclei_results)}")
    log.info(f"  gf pattern matches: {sum(len(v) for v in gf_results.values())}")
    log.info(f"  takeover flags: {len(takeover_results)}")

    return {
        "shodan": shodan_results,
        "waf": waf_results,
        "nuclei": nuclei_results,
        "gf": gf_results,
        "takeover": takeover_results,
    }


def run_phase7(cfg: Config, high_priority_urls: set, wordlist_path: str | None = None) -> dict:
    """Phase 7: Content Discovery — dir bruteforce on high-priority hosts only, then screenshots."""
    log.info(f"=== PHASE 7: CONTENT DISCOVERY ({len(high_priority_urls)} high-priority hosts) ===")

    log.info("Step 18: directory bruteforce (ffuf / dirsearch) — high priority hosts only")
    dirs = dir_bruteforce.run_content_discovery_stage(cfg, high_priority_urls, wordlist_path)

    log.info("Step 19: screenshots (EyeWitness)")
    screens_dir = screenshots.eyewitness_capture(cfg, high_priority_urls)

    log.info("=== PHASE 7 COMPLETE ===")
    log.info(f"  directory hits: {len(dirs)}")
    log.info(f"  screenshots dir: {screens_dir}")

    return {"dirs": dirs, "screens_dir": screens_dir}


def run_phase8(cfg: Config) -> dict:
    """Phase 8: Cloud Recon — bucket discovery."""
    log.info("=== PHASE 8: CLOUD RECON ===")

    log.info("Step 20: bucket discovery (greyhatwarfare -> awscli -> lazys3 -> S3Scanner)")
    buckets = bucket_discovery.run_bucket_discovery_stage(cfg)

    log.info("=== PHASE 8 COMPLETE ===")
    log.info(f"  bucket findings: {len(buckets)}")

    return {"buckets": buckets}


def run_phase9(cfg: Config) -> dict:
    """Phase 9: DNS + Infra — deep/active DNS enumeration."""
    log.info("=== PHASE 9: DNS + INFRA ===")

    log.info("Step 21: deep DNS (dnsrecon + amass active)")
    dns_lines = deep_dns.run_deep_dns_stage(cfg)

    log.info("=== PHASE 9 COMPLETE ===")
    log.info(f"  deep DNS output lines: {len(dns_lines)}")

    return {"dns_full": dns_lines}


def run_pipeline(
    cfg: Config,
    tier: int = 1,
    wordlist_path: str | None = None,
    dir_wordlist_path: str | None = None,
) -> dict:
    """
    Single entrypoint implementing Phase 14's tiered execution model, plus
    Phase 10 (scoring), Phase 12 (SQLite storage — store everything, diff
    across runs), and Phase 13 (final prioritized report) at the end.

    Tier 1 runs regardless of cfg.authorized (passive only). Tiers 2-4
    require target.authorized: true, same as the granular phaseN functions.
    """
    if tier not in TIER_PHASES:
        raise ValueError(f"tier must be 1-4, got {tier}")
    phases_to_run = TIER_PHASES[tier]
    log.info(f"=== PIPELINE START — tier {tier} ({', '.join(phases_to_run)}) ===")

    store = Storage(cfg.db_path)
    store.start_run(cfg.domain)

    p1 = run_phase1(cfg, wordlist_path=wordlist_path)
    new_subs = store.save_subdomains(p1["subdomains"])
    store.save_ips(p1["asn_ip"].get("ips", []))
    log.info(f"Storage diff: {len(new_subs)} subdomains never seen in a prior run")

    p2 = p3 = p4 = p5 = None

    if "phase2" in phases_to_run:
        if not cfg.authorized:
            log.error(
                f"Tier {tier} requires target.authorized: true for active phases. "
                "Stopping after Phase 1 (Tier 1 results are still complete)."
            )
            store.close()
            return _finalize(cfg, tier_reached=1)

        p2 = run_phase2(cfg, p1["subdomains"])
        store.save_urls(p2["live_urls"])

    if "phase3" in phases_to_run and p2:
        p3 = run_phase3(cfg, p2["resolved_hosts"], p2["httpx_records"])
        store.save_ports(p3["ports"])

    if "phase4" in phases_to_run and p2:
        p4 = run_phase4(cfg, p2["live_urls"])
        store.save_urls(p4["final_urls"])

    if "phase5" in phases_to_run and p4:
        p5 = run_phase5(cfg, p4["final_urls"])
        if p5["secrets"]:
            store.save_findings_bulk("secret", p5["secrets"])
        if p5["github_findings"]:
            store.save_findings_bulk("github_leak", p5["github_findings"])

    # Phase 10 — score targets as soon as we have enough signal (needs
    # final_urls + ports + httpx records + endpoints)
    if p4 and p3:
        scoring.score_targets(
            cfg,
            final_urls=p4["final_urls"],
            port_pairs=p3["ports"],
            httpx_records=p2["httpx_records"],
            endpoints=(p5["endpoints"] if p5 else set()),
        )

    if "phase6" in phases_to_run and p4 and p3 and p2:
        p6 = run_phase6(cfg, p4["final_urls"], p2["resolved_hosts"], p3["ports"])
        if p6["takeover"]:
            store.save_findings_bulk("takeover", p6["takeover"])
        if p6["nuclei"]:
            store.save_findings_bulk("nuclei", p6["nuclei"])

    if "phase7" in phases_to_run and p3 and p2:
        hv_hosts = set(p3["high_value_hosts"])
        high_priority_urls = {u for u in p2["live_urls"] if any(h in u for h in hv_hosts)} or p2["live_urls"]
        run_phase7(cfg, high_priority_urls, wordlist_path=dir_wordlist_path)

    if "phase8" in phases_to_run:
        p8 = run_phase8(cfg)
        if p8["buckets"]:
            store.save_findings_bulk("bucket", p8["buckets"])

    if "phase9" in phases_to_run:
        run_phase9(cfg)

    store.close()
    return _finalize(cfg, tier_reached=tier)


def _finalize(cfg: Config, tier_reached: int) -> dict:
    """Phase 13 — Final Output: combine everything into the prioritized report."""
    log.info("=== GENERATING FINAL REPORT ===")
    master = report_mod.generate_master_report(cfg)
    summary_text = report_mod.generate_final_summary(cfg)
    log.info("\n" + summary_text)
    return {"tier_reached": tier_reached, "master_report": master, "summary": summary_text}
