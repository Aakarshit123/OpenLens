# OpenLens — Automated OSINT Intelligence Framework

By Aakarshit Bargotra & Kanav Samotra

> For authorized security research and bug bounty use only. Never run against targets you don't own or have explicit written permission to test.

---

## Overview

OpenLens is a modular, CLI-based OSINT framework that automates the full reconnaissance pipeline for a target domain. It covers subdomains, DNS, emails, open ports, Google dorks, breach checks, directory busting, and JavaScript analysis, then outputs a clean HTML or JSON report.

Built for security researchers and bug bounty hunters who want to skip the manual recon and focus on finding real vulnerabilities.

---

## Features

- Subdomain Enumeration — passive (crt.sh, HackerTarget) and active brute-force with threading
- DNS & WHOIS — A, AAAA, MX, NS, TXT, CNAME, SOA records plus full WHOIS data
- Email Harvesting — Bing scraping, site crawling (contact/about/team pages), Hunter.io API
- Shodan Scanner — open ports, services, software versions, CVE flagging
- Google Dorks — 15+ dork categories with clickable search URLs
- Breach Check — HaveIBeenPwned v3 API with breach name, date, and leaked data types
- Directory Busting — concurrent threaded directory and file discovery
- JS Scanner — crawls and downloads JS files, extracts API endpoints, detects potential secrets like keys, tokens, and hardcoded credentials
- Report Generator — dark-themed HTML report and structured JSON output

---

## Project Structure

```
OpenLens/
├── main.py                  # CLI entry point
├── config.py                # API keys — do not commit with real keys
├── requirements.txt
├── modules/
│   ├── dns_whois.py         # DNS records + WHOIS lookup
│   ├── subdomain.py         # Passive + active subdomain enumeration
│   ├── email_harvest.py     # Email scraping + Hunter.io
│   ├── shodan_scan.py       # Shodan open ports & CVEs
│   ├── google_dorks.py      # Google dork query generator
│   ├── breach_check.py      # HaveIBeenPwned breach checker
│   ├── dir_buster.py        # Directory & file brute-forcing
│   ├── js_scanner.py        # JS file crawling & secret detection
│   └── report_gen.py        # HTML + JSON report generator
└── reports/                 # Generated reports saved here
```

---

## Setup

### Requirements

- Python 3.10+
- pip

### 1. Clone the repository

```
git clone https://github.com/Aakarshit123/OpenLens.git
cd OpenLens
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Configure API keys (optional but recommended)

Edit config.py and add your keys:

```
SHODAN_API_KEY = "your_shodan_key"      # https://account.shodan.io/
HIBP_API_KEY   = "your_hibp_key"        # https://haveibeenpwned.com/API/Key
HUNTER_API_KEY = "your_hunter_key"      # https://hunter.io/
```

Shodan is needed for port scanning. HIBP is needed for breach checking. Hunter.io improves email harvesting. All three are optional — the other modules run without them.

---

## Usage

Run all modules against a target:

```
python main.py -t example.com --all
```

Run specific modules:

```
python main.py -t example.com --dns --subdomains --emails
python main.py -t example.com --dirb --jscan
```

Choose output format:

```
python main.py -t example.com --all --output html
python main.py -t example.com --all --output json
python main.py -t example.com --all --output all
```

### Available flags

| Flag | Description |
|------|-------------|
| -t, --target | Target domain (required) |
| --subdomains | Run subdomain enumeration |
| --dns | Run DNS/WHOIS scan |
| --emails | Run email harvesting |
| --shodan | Run Shodan scan (API key required) |
| --dorks | Generate Google dork queries |
| --breach | Check emails for breaches (API key required) |
| --dirb | Run directory busting |
| --jscan | Crawl JS files and extract endpoints and potential secrets |
| --all | Run all modules |
| --output | Report format: html, json, or all (default: html) |
| --output-dir | Output directory (default: reports/) |

---

## Report Output

The generated HTML report includes:

- Summary stats bar (subdomains, emails, ports, breaches, JS files)
- Full DNS and WHOIS breakdown
- Subdomain table with IPs and discovery sources
- Email list with names and positions
- Open ports with CVE flags
- Clickable Google dork links
- JS file list with extracted API endpoints and flagged potential secrets
- Breach status per email

---

## Legal & Ethical Use

OpenLens uses only publicly available data sources — DNS records, certificate transparency logs, search engine indexing, and public APIs. It does not exploit vulnerabilities or interact with targets in any intrusive way.

Always obtain explicit written authorization before scanning any target you do not own. Unauthorized use may violate local, national, or international laws. The authors accept no liability for misuse.

---

## Roadmap

- Wayback Machine historical URL crawl
- Technology stack fingerprinting
- GitHub and Pastebin exposure check
- PDF report export
- Web UI dashboard

---

## Authors

- Aakarshit Bargotra — github.com/Aakarshit123
- Kanav Samotra
