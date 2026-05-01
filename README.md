# 🔍 OSINT-EX — Automated OSINT Intelligence Framework

> **For authorized security research and bug bounty use only. Never run against targets you don't own or have explicit written permission to test.**

A modular, CLI-based OSINT framework that automates reconnaissance on a target domain — subdomains, DNS, emails, open ports, Google dorks, and breach checks — and outputs a clean HTML/JSON report.

---

## 👥 Team Members
- Member 1 — Recon Modules (DNS/WHOIS, Subdomains, Shodan)
- Member 2 — Intelligence Modules (Email Harvesting, Google Dorks, Breach Check, Report)

---

## 📁 Project Structure

```
osint-framework/
├── main.py                  # CLI entry point
├── config.py                # API keys (DO NOT commit to GitHub)
├── requirements.txt
├── modules/
│   ├── dns_whois.py         # DNS records + WHOIS lookup
│   ├── subdomain.py         # Passive + active subdomain enumeration
│   ├── email_harvest.py     # Email scraping + Hunter.io
│   ├── shodan_scan.py       # Shodan open ports & CVEs
│   ├── google_dorks.py      # Google dork query generator
│   ├── breach_check.py      # HaveIBeenPwned breach checker
│   └── report_gen.py        # HTML + JSON report generator
└── reports/                 # Output reports saved here
```

---

## ⚙️ Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API keys (optional but recommended)
Edit `config.py`:
```python
SHODAN_API_KEY = "your_shodan_key"       # https://account.shodan.io/
HIBP_API_KEY   = "your_hibp_key"         # https://haveibeenpwned.com/API/Key
HUNTER_API_KEY = "your_hunter_key"       # https://hunter.io/
```

---

## 🚀 Usage

### Run all modules
```bash
python main.py -t example.com --all
```

### Run specific modules
```bash
python main.py -t example.com --dns --subdomains --emails
```

### Choose output format
```bash
python main.py -t example.com --all --output html
python main.py -t example.com --all --output json
python main.py -t example.com --all --output all
```

### All flags
| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target domain (required) |
| `--subdomains` | Run subdomain enumeration |
| `--dns` | Run DNS/WHOIS scan |
| `--emails` | Run email harvesting |
| `--shodan` | Run Shodan scan (API key needed) |
| `--dorks` | Generate Google dork queries |
| `--breach` | Check emails for breaches (API key needed) |
| `--all` | Run all modules |
| `--output` | Report format: html, json, all |
| `--output-dir` | Output directory (default: reports/) |

---

## 📦 Modules

### 1. DNS & WHOIS (`dns_whois.py`)
- Queries A, AAAA, MX, NS, TXT, CNAME, SOA records
- Fetches full WHOIS registration data
- Resolves IP + reverse DNS

### 2. Subdomain Enumeration (`subdomain.py`)
- **Passive**: crt.sh certificate transparency logs, HackerTarget API
- **Active**: wordlist brute-force with concurrent threading
- Resolves each subdomain to its IP

### 3. Email Harvesting (`email_harvest.py`)
- Scrapes Bing search results for emails
- Crawls target website (contact, about, team pages)
- Hunter.io API integration (optional)

### 4. Shodan Scanner (`shodan_scan.py`)
- Finds open ports and running services
- Identifies software versions and CPEs
- Flags known CVEs on discovered services

### 5. Google Dorks (`google_dorks.py`)
- Generates 15+ targeted dork queries across categories:
  - Sensitive files (pdf, sql, env, yaml, bak)
  - Login & admin panels
  - Open directory listings
  - Error & debug pages
  - Credentials and API keys
  - GitHub/Pastebin mentions
- Produces clickable Google search URLs

### 6. Breach Check (`breach_check.py`)
- Checks each harvested email against HaveIBeenPwned v3 API
- Returns breach name, date, and leaked data types

### 7. Report Generator (`report_gen.py`)
- **HTML**: Dark-themed, professional report with all findings organized by module
- **JSON**: Machine-readable structured output for further processing

---

## 🛡️ Legal & Ethical Use

This tool performs **passive and semi-passive reconnaissance** using:
- Public DNS data
- Public certificate transparency logs
- Search engine indexing
- Public APIs (Shodan, HIBP, Hunter.io)

**Always ensure you have written authorization before testing any target you don't own.**

---

## 📊 Sample Report Output

Running against your own domain generates an HTML report with:
- Summary stats bar (subdomains, emails, ports, breaches)
- Full DNS/WHOIS breakdown
- Subdomain table with IPs and sources
- Email list with names/positions
- Open ports with CVE flags
- Google dork links (click to search)
- Breach status per email

---

## 🔮 Future Improvements
- [ ] LinkedIn employee scraping
- [ ] Wayback Machine historical URL crawl
- [ ] Technology stack fingerprinting (Wappalyzer-style)
- [ ] Slack/Trello/GitHub API key exposure check
- [ ] Export to PDF
- [ ] Web UI dashboard
