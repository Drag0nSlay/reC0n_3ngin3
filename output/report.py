"""
output/report.py

Combines every phase's output files into one unified report:
  - data/processed/master_report.json   (structured, machine-readable)
  - data/processed/MASTER_REPORT.md      (human-readable, prioritized)

Reads whatever files exist under raw_dir/processed_dir — missing files
(tool not installed, phase not run, nothing found) are treated as empty,
never as errors, so this works no matter how far the pipeline got.

Usage (standalone, after any run):
    python -m output.report --config config/settings.yaml
"""

from __future__ import annotations
import argparse
import json
import os
from datetime import datetime, timezone
from typing import List

from core.config import Config
from utils.logger import setup_logging, get_logger

log = get_logger("output.report")


# (filename, friendly label, phase, base_dir — "raw" or "processed")
FILES = [
    ("all_subdomains_raw.txt", "Passive subdomains (raw)", "Phase 1", "raw"),
    ("final_subdomains.txt", "Final subdomains", "Phase 1", "processed"),
    ("cidr.txt", "CIDR ranges", "Phase 1", "raw"),
    ("ips.txt", "Expanded IPs", "Phase 1", "raw"),
    ("resolved_hosts_only.txt", "Resolved hosts", "Phase 2", "processed"),
    ("live_domains.txt", "Live hosts (httpx)", "Phase 2", "processed"),
    ("ports.txt", "Open host:port pairs", "Phase 3", "processed"),
    ("services.txt", "Service enumeration (nmap)", "Phase 3", "processed"),
    ("final_urls.txt", "All discovered URLs", "Phase 4", "processed"),
    ("js_files.txt", "JS files", "Phase 5", "processed"),
    ("endpoints.txt", "Discovered endpoints", "Phase 5", "processed"),
    ("secrets.txt", "Secrets found (redacted)", "Phase 5", "processed"),
    ("github_secrets.txt", "GitHub leakage findings", "Phase 5", "processed"),
    ("waf.txt", "WAF detections", "Phase 6", "processed"),
    ("nuclei.txt", "nuclei findings (safe templates)", "Phase 6", "processed"),
    ("interesting_params.txt", "gf pattern matches", "Phase 6", "processed"),
    ("takeover.txt", "Subdomain takeover flags", "Phase 6", "processed"),
    ("dirs.txt", "Directory bruteforce hits", "Phase 7", "processed"),
    ("buckets.txt", "Cloud bucket findings", "Phase 8", "processed"),
    ("dns_full.txt", "Deep DNS output", "Phase 9", "processed"),
]

# Files whose presence (non-empty) signals something worth a human's
# immediate attention — surfaced at the top of the markdown report.
HIGH_SIGNAL_FILES = {
    "secrets.txt": "Hard-coded secrets found in JS",
    "github_secrets.txt": "Secrets/leaks found in public GitHub repos",
    "takeover.txt": "Possible subdomain takeover",
    "buckets.txt": "Publicly accessible cloud storage",
    "nuclei.txt": "nuclei template matches",
}


def _read_lines(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def _read_jsonl(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def generate_master_report(cfg: Config) -> dict:
    report = {
        "target": cfg.domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authorized": cfg.authorized,
        "sections": {},
    }

    for fname, label, phase, base in FILES:
        base_dir = cfg.raw_dir if base == "raw" else cfg.processed_dir
        full_path = os.path.join(base_dir, fname)
        lines = _read_lines(full_path)
        report["sections"][fname] = {
            "label": label,
            "phase": phase,
            "count": len(lines),
            "items": lines,
        }

    shodan_path = os.path.join(cfg.processed_dir, "shodan.jsonl")
    shodan_records = _read_jsonl(shodan_path)
    report["sections"]["shodan.jsonl"] = {
        "label": "Shodan host intelligence",
        "phase": "Phase 6",
        "count": len(shodan_records),
        "items": shodan_records,
    }

    # Top-level counts for quick scanning
    report["summary"] = {
        name: data["count"] for name, data in report["sections"].items()
    }

    json_path = os.path.join(cfg.processed_dir, "master_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    log.info(f"Master JSON report -> {json_path}")

    _write_markdown_report(cfg, report)
    return report


def generate_final_summary(cfg: Config) -> str:
    """
    Phase 13 — Final Output.
    A short, human-first executive summary — counts + prioritized target
    tiers + interesting signals + potential issues. Deliberately NOT a
    raw dump: full detail always lives in master_report.json / the
    individual .txt files, this is what a human reads first.

    Output: data/processed/FINAL_REPORT.txt
    """
    def _read(fname):
        return _read_lines(os.path.join(cfg.processed_dir, fname))

    subdomains = _read("final_subdomains.txt")
    live_hosts = _read("live_domains.txt")
    ports = _read("ports.txt")
    high_targets = _read("high_targets.txt")
    medium_targets = _read("medium_targets.txt")
    endpoints_with_params = [e for e in _read("interesting_params.txt") if not e.startswith("#")]
    js_files = _read("js_files.txt")
    nuclei = _read("nuclei.txt")
    takeover = _read("takeover.txt")
    secrets = _read("secrets.txt")
    buckets = _read("buckets.txt")

    lines: List[str] = []
    lines.append("REPORT:")
    lines.append(f"Total Subdomains: {len(subdomains)}")
    lines.append(f"Live Hosts: {len(live_hosts)}")
    lines.append(f"Open Ports: {len(ports)}")
    lines.append("")

    lines.append("HIGH VALUE:")
    if high_targets:
        for t in high_targets[:25]:
            lines.append(f"- {t}")
        if len(high_targets) > 25:
            lines.append(f"- ...and {len(high_targets) - 25} more (see high_targets.txt)")
    else:
        lines.append("- none flagged")
    lines.append("")

    lines.append("INTERESTING:")
    if medium_targets:
        lines.append(f"- {len(medium_targets)} medium-priority targets (see medium_targets.txt)")
    if endpoints_with_params:
        lines.append(f"- {len(endpoints_with_params)} endpoints with params (see interesting_params.txt)")
    if js_files:
        lines.append(f"- {len(js_files)} JS files (see js_files.txt)")
    if not (medium_targets or endpoints_with_params or js_files):
        lines.append("- nothing notable")
    lines.append("")

    lines.append("POTENTIAL ISSUES:")
    if nuclei:
        lines.append(f"- {len(nuclei)} nuclei findings (see nuclei.txt)")
    if takeover:
        lines.append(f"- {len(takeover)} subdomain takeover candidates (see takeover.txt)")
    if secrets:
        lines.append(f"- {len(secrets)} redacted secret findings (see secrets.txt)")
    if buckets:
        lines.append(f"- {len(buckets)} cloud bucket findings (see buckets.txt)")
    if not (nuclei or takeover or secrets or buckets):
        lines.append("- none found")

    text = "\n".join(lines) + "\n"
    out_path = os.path.join(cfg.processed_dir, "FINAL_REPORT.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)

    log.info(f"Final executive report -> {out_path}")
    return text


def _write_markdown_report(cfg: Config, report: dict) -> None:
    md_path = os.path.join(cfg.processed_dir, "MASTER_REPORT.md")
    lines: List[str] = []

    lines.append(f"# Recon Report — {report['target']}")
    lines.append(f"_Generated: {report['generated_at']}_\n")

    # --- High-signal findings first (principle #5: actionable, not raw dumps) ---
    lines.append("## 🚩 High-Signal Findings\n")
    any_high_signal = False
    for fname, description in HIGH_SIGNAL_FILES.items():
        section = report["sections"].get(fname)
        if section and section["count"] > 0:
            any_high_signal = True
            lines.append(f"- **{description}** ({fname}): {section['count']} item(s)")
    if not any_high_signal:
        lines.append("- None of the high-signal categories produced findings.")
    lines.append("")

    # --- Summary counts table ---
    lines.append("## Summary\n")
    lines.append("| File | Phase | Label | Count |")
    lines.append("|---|---|---|---|")
    for fname, data in report["sections"].items():
        lines.append(f"| `{fname}` | {data['phase']} | {data['label']} | {data['count']} |")
    lines.append("")

    # --- Detail sections (capped preview, full data lives in the JSON/txt files) ---
    lines.append("## Details\n")
    for fname, data in report["sections"].items():
        if data["count"] == 0:
            continue
        lines.append(f"### {data['label']} (`{fname}`) — {data['count']}")
        preview = data["items"][:20]
        for item in preview:
            item_str = item if isinstance(item, str) else json.dumps(item)
            lines.append(f"- {item_str}")
        if data["count"] > 20:
            lines.append(f"- _...and {data['count'] - 20} more, see `{fname}`_")
        lines.append("")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log.info(f"Master Markdown report -> {md_path}")


def main():
    p = argparse.ArgumentParser(description="Combine all reC0n_3ngin3 phase outputs into one report")
    p.add_argument("--config", default="config/settings.yaml")
    args = p.parse_args()

    cfg = Config(args.config)
    setup_logging(cfg.log_level, cfg.log_file)
    generate_master_report(cfg)
    print(generate_final_summary(cfg))


if __name__ == "__main__":
    main()
