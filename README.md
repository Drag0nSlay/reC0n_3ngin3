<div align="center">

# 🕵️ reC0n_3ngin3

**A tiered, orchestrated reconnaissance pipeline — from passive OSINT to prioritized findings, in one command.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)
![Tiers](https://img.shields.io/badge/tiers-4-orange.svg)

</div>

---

## ⚡ What it does

`reC0n_3ngin3` wraps the tools you already trust — `subfinder`, `httpx`,
`naabu`, `nmap`, `nuclei`, `katana`, `subzy`, and more — into a single
**14-phase orchestrated pipeline**:

```
Passive Enum → Resolution → Port Scan → Crawl → JS/Secrets →
Vuln Signals → Content Discovery → Cloud Recon → Deep DNS →
Scoring → Storage → Prioritized Report
```

No more juggling a dozen terminal tabs and manually merging text files.
One command in, one prioritized report out — with **color-coded console
output** so you can tell phases and severity apart at a glance (auto
disables when output is piped/redirected to a file).

## 🎯 Tiered execution

Don't run everything blindly. Pick the tier that matches what you need:

| Tier | What runs | Speed | Touches target? |
|:---:|---|:---:|:---:|
| **1** | Passive OSINT only (crt.sh, VT, Chaos, GitHub, ASN/IP) | ⚡ Fast | ❌ No |
| **2** | + DNS resolution, alive detection, port scanning | 🚶 Medium | ✅ Yes |
| **3** | + Historical/live URL crawling, JS + secret analysis | 🐢 Slower | ✅ Yes |
| **4** | + nuclei, dir bruteforce, cloud buckets, deep DNS — everything | 🐌 Full run | ✅ Yes |

```bash
python main.py --config config/settings.yaml --tier 1   # safe default
python main.py --config config/settings.yaml --tier 4   # full pipeline
```

## 🧰 Subcommands

Instead of remembering individual tool syntax (`amass enum`, `subfinder -d`,
`nuclei -l`, etc.), use one `main.py` subcommand that runs the equivalent
operation across **all installed tools** automatically:

```bash
python main.py enum -d example.com        # passive subdomain enum (all sources)
python main.py intel -d example.com       # org-wide infrastructure intel
python main.py subdomain -d example.com   # full subdomain pipeline → final_subdomains.txt
python main.py resolve -d example.com     # DNS resolution + alive detection
python main.py scan -d example.com        # port scan + service enumeration
python main.py crawl -d example.com       # URL collection (historical + live)
python main.py secrets -d example.com     # JS + secret analysis + GitHub leaks
python main.py vuln -d example.com        # nuclei + takeover + WAF + gf
python main.py discover -d example.com    # directory bruteforce + screenshots
python main.py cloud -d example.com       # S3/bucket discovery
python main.py dns -d example.com         # deep/active DNS enumeration
python main.py full -d example.com        # run everything (= --tier 4)
```

| Subcommand | Tools it runs | Active? |
|---|---|:---:|
| `enum` | subfinder, assetfinder, amass passive, crt.sh, VT, Chaos, GitHub | ❌ |
| `intel` | amass intel -org, ARIN, bgp.he.net, asnmap, Shodan | ❌ |
| `subdomain` | enum + intel + shuffledns brute + permutation + recursive | ⚠️ Brute step |
| `resolve` | dnsx, httpx | ✅ |
| `scan` | naabu, rustscan, nmap -sV -sC | ✅ |
| `crawl` | waybackurls, gau, katana | ✅ |
| `secrets` | LinkFinder, SecretFinder, mantra, trufflehog, gitgraber | ✅ |
| `vuln` | nuclei (safe), subzy, wafw00f, gf | ✅ |
| `discover` | ffuf/dirsearch, EyeWitness | ✅ |
| `cloud` | greyhatwarfare, aws s3, lazys3, S3Scanner | ✅ |
| `dns` | dnsrecon, amass active | ✅ |
| `full` | Everything above | ✅ |

Every subcommand accepts `-d <domain>` (overrides settings.yaml) and
`-c <config>` (custom config path). The old `--tier` / `--until` syntax
still works exactly as before for backward compatibility.

## 🔒 Authorized use only

> **This tool sends real network traffic from Tier 2 onward.** Only run
> it against targets you **own** or have **explicit written
> authorization** to test (bug bounty scope, signed pentest contract).

The `authorized` flag in `config/settings.yaml` is a hard gate — every
active module refuses to run unless it's explicitly `true`. Tier 1
(passive-only) runs regardless, since it never sends a single packet to
the target.

Unauthorized scanning may violate the CFAA (US), Computer Misuse Act
(UK), IT Act 2000 (India), or equivalent laws elsewhere. You are
responsible for how you use this tool.

## 🚀 Quick start

```bash
git clone https://github.com/Drag0nSlay/reC0n_3ngin3.git
cd reC0n_3ngin3

cp config/settings.example.yaml config/settings.yaml
# edit config/settings.yaml → add your API keys + target domain

pip install -r requirements.txt --break-system-packages

python main.py --config config/settings.yaml --tier 1
```

> `config/settings.yaml` is gitignored — never commit real API keys or
> `authorized: true`.

> **Kali users:** the `httpx` binary name clashes with Python's `httpx`
> package in Kali's repos. Install ProjectDiscovery's version as
> `httpx-toolkit` (`sudo apt install -y httpx-toolkit`) and set
> `paths.httpx: "httpx-toolkit"` in `settings.yaml`.

## 📂 What you get

Output is **domain-scoped** — running the pipeline against a different
`target.domain` never overwrites another target's results:

```
data/processed/<domain>/FINAL_REPORT.txt     ← start here: counts + HIGH/MEDIUM/LOW targets + issues
data/processed/<domain>/MASTER_REPORT.md     ← full detail, section per phase
data/processed/<domain>/master_report.json   ← same, machine-readable
data/processed/recon.sqlite3                 ← shared across all domains — reruns auto-diff against past scans
```

Regenerate the report anytime without rerunning the pipeline:

```bash
python -m output.report --config config/settings.yaml
```

## 🧩 Pipeline phases

| # | Phase | # | Phase |
|---|---|---|---|
| 1 | Target Enumeration | 9 | DNS + Infra |
| 2 | Resolution Layer | 10 | Intelligence Engine (scoring) |
| 3 | Network Scanning | 11 | Automation / Orchestration |
| 4 | Crawling + Endpoints | 12 | Data Handling (SQLite) |
| 5 | JS + Secret Analysis | 13 | Final Output (report) |
| 6 | Vulnerability Signals | 14 | Tiered Execution Strategy |
| 7 | Content Discovery | 15 | Automation Boundaries* |
| 8 | Cloud Recon | | |

*\*Data collection, filtering, and tagging are automated. Exploitation
and heavy fuzzing are deliberately **not** — nuclei is capped to
info/low severity + non-intrusive tags, masscan needs a second explicit
confirmation, and directory bruteforcing only ever runs against a
curated high-priority host list.*

## 🆕 Recently added

- **`extra_args` escape hatch** — every tool wrapper (all 19 CLI tools)
  now accepts custom flags via `settings.yaml`:
  ```yaml
  extra_args:
    nmap: ["-T4", "--script=vuln"]
    nuclei: ["-tags", "cve,exposure"]
    subfinder: ["-recursive"]
  ```
  Covers subcommands/flags this project doesn't wire up individually
  (nmap `--script`, nuclei `-tags`, subfinder `-recursive`, ffuf `-mc`,
  etc.) without needing a code change per flag. Empty by default — you
  are responsible for staying within your authorized scope with
  anything you add here.
- **`amass intel -org`** — organization-wide ASN/netblock discovery via
  WHOIS (set `target.org_name` in config). Written to a separate
  `org_intel.txt` — surfaces leads, not confirmed subdomains, so it's
  never auto-merged into the main results.
- **`naabu -passive`** — port data from Shodan's free InternetDB API,
  zero packets sent to the target. Runs alongside the active naabu
  sweep in Phase 3 as a free extra signal.
- **`httpx -favicon`** — mmh3 favicon hash on every live host, useful
  for Shodan/Censys favicon-based infrastructure pivoting.

## 🛠️ Tools this wraps

`subfinder` `assetfinder` `amass` `asnmap` `mapcidr` `shuffledns` `dnsx`
`httpx` `naabu` `rustscan` `masscan` `nmap` `waybackurls` `gau` `katana`
`wafw00f` `nuclei` `gf` `subzy` `ffuf` `dirsearch` `EyeWitness`
`dnsrecon` — all optional; anything not installed is skipped
gracefully, with a log warning, never a crash.

## 🚧 Work in progress

This tool is still under active development. If you run into a bug, a
tool wrapper that doesn't match your installed version's flags, or a
missing feature — feel free to open an issue or a PR. Contributions are
welcome, big or small.

**Recently fixed:** `scan.naabu_top_ports` in `settings.yaml` wasn't
actually being passed through to the naabu scan call (always used a
hardcoded default regardless of config) — now wired correctly.

## 📄 License

MIT — see [LICENSE](LICENSE).
