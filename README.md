WAF Detector

A simple, cross-platform Web Application Firewall (WAF) fingerprinting tool. It probes a target (domain, URL, or IP), inspects HTTP headers/cookies, and reports likely WAF/CDN vendors.

Version: 2.8 • Author: Dang3rXgh0st
Note: Use legally and only with permission.

Features

Single target or batch scanning from file

Interactive menu mode

Optional “aggressive” probes to help trigger filtering

Virtual-host testing with custom Host header

Export pretty HTML and machine-readable XML reports

Requirements

Python 3.8+

pip and the requests library

Installation
Windows (PowerShell)
py -m venv .venv
. .\.venv\Scripts\Activate.ps1
py -m pip install -U requests

Linux/macOS (Bash)
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -U requests

Usage
Quick start (single target)
# Linux/macOS
python3 firewall_detect.py example.com

# Windows
py firewall_detect.py example.com

Interactive menu
python3 firewall_detect.py -i

Batch scan from file

Create targets.txt with one domain/IP/URL per line, then:

python3 firewall_detect.py -F targets.txt

Export reports (HTML + XML)
# Save reports to ./reports with timestamped names
python3 firewall_detect.py -F targets.txt -x

# Choose directory/name and auto-open in browser
python3 firewall_detect.py -F targets.txt -x -d reports -o myscan -r

Selected options
-i, --menu               Interactive menu
-F, --input-file FILE    Batch scan (one target per line)
-x, --export             Write HTML + XML reports
-d, --out-dir DIR        Reports directory (default: ./reports)
-o, --output NAME        Base filename for reports
-r, --open-reports       Open generated reports in default browser
-H, --host HOSTNAME      Override Host header (IP + vhost testing)
--force-scheme VALUE     Force http or https
-P, --port PORT          Custom port
-k, --insecure           Skip TLS verification
-T, --timeout SECONDS    Request timeout (e.g., 8)
-u, --user-agent STRING  Custom User-Agent
-a, --aggressive         Extra probes to help trigger filtering

Examples
# Single target + export
python3 firewall_detect.py https://example.com -x

# Scan by IP but send Host: example.com
python3 firewall_detect.py http://203.0.113.10 -H example.com -x

# Force HTTP for a domain
python3 firewall_detect.py example.com --force-scheme http

Output

HTML: readable table + per-target details

XML: structured data for scripts/parsers

Default location: ./reports/ with filename like wafscan_YYYYMMDD_HHMMSS

Project structure
WAF_Detector/
├─ firewall_detect.py
├─ README.md
├─ requirements.txt
├─ LICENSE
├─ .gitignore
├─ targets.txt          # optional
└─ reports/             # created by -x

