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
One command in, one prioritized report out.

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
git clone https://github.com/<your-username>/reC0n_3ngin3.git
cd reC0n_3ngin3

cp config/settings.example.yaml config/settings.yaml
# edit config/settings.yaml → add your API keys + target domain

pip install -r requirements.txt --break-system-packages

python main.py --config config/settings.yaml --tier 1
```

> `config/settings.yaml` is gitignored — never commit real API keys or
> `authorized: true`.

## 📂 What you get

After a run, check:

```
data/processed/FINAL_REPORT.txt     ← start here: counts + HIGH/MEDIUM/LOW targets + issues
data/processed/MASTER_REPORT.md     ← full detail, section per phase
data/processed/master_report.json   ← same, machine-readable
data/processed/recon.sqlite3        ← everything stored — reruns auto-diff against past scans
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

## 📄 License

MIT — see [LICENSE](LICENSE).