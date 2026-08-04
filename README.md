# RedScanner v0.3

Async Python security orchestrator for web application and CDN red team engagements.
Chains external recon/vuln tools into a single pipeline with structured JSON, HTML,
and Markdown output.

## What's new in v0.3

| Feature | Details |
|---------|---------|
| CORS scanner | OWASP WSTG-CLIENT-07 — wildcard, origin reflection, credentialed CORS, suffix spoofing |
| TLS scanner | OWASP WSTG-CRYP-01 — testssl.sh primary, openssl fallback; legacy protocol + cert checks |
| Directory brute-force | OWASP WSTG-CONF-05 — gobuster → ffuf → built-in 50-path probe |
| CDN bypass scanner | Origin IP exposure, IP header spoofing, Host injection, cache deception |
| CVSS v3.1 scores | All new modules populate `cvss_score`; HTML report now includes CVSS column |
| `--resume` | Resumes an interrupted scan from the last completed module |
| `--target-file` | Batch scan from a text file of targets (one per line) |
| New profiles | `web-hardening`, `discovery`, `cdn-test` added to red_plan.json |

## Architecture

```
main.py
├── core/
│   ├── config.py        ScanConfig dataclass (all scan parameters)
│   ├── models.py        Vulnerability / ScanResult dataclasses
│   ├── tool_runner.py   async subprocess wrapper
│   ├── red_plan.py      red_plan.json loader
│   ├── db.py            SQLite state store
│   ├── surface.py       URL surface aggregation helpers
│   ├── domain_scope.py  in-scope domain filter
│   └── crawl_fallback.py built-in crawler (when xcrawl3r absent)
└── modules/
    ├── recon.py              subfinder+assetfinder+httpx+xcrawl3r
    ├── wayback_enricher.py   waybackurls+gau URL enrichment
    ├── naabu_scanner.py      port scan
    ├── vuln_scanner.py       nuclei
    ├── xss_scanner.py        dalfox
    ├── sqli_scanner.py       sqlmap
    ├── api_leak_scanner.py   endpoint / key leak detection
    ├── header_scanner.py     HTTP security header audit (WSTG-CONF-07)
    ├── cors_scanner.py       CORS misconfiguration (WSTG-CLIENT-07)   ← v0.3
    ├── tls_scanner.py        TLS/SSL assessment (WSTG-CRYP-01)        ← v0.3
    ├── dirbust_scanner.py    directory enumeration (WSTG-CONF-05)     ← v0.3
    ├── cdn_bypass_scanner.py CDN/WAF bypass tests                     ← v0.3
    ├── nikto_scanner.py      nikto web server scan
    └── report_generator.py   HTML + JSON + Markdown reports           ← v0.3 CVSS
```

## Module execution order

```
recon → wayback → naabu → nuclei → xss → sqli → api_leak →
header_check → cors → tls → dirbust → cdn_bypass → nikto
```

After each module completes, `resume.cfg` is updated. On `--resume`, completed
modules are skipped and recon state is restored from output files.

## Setup

### Required (core pipeline)

```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Python tools
pip install dalfox   # or go install github.com/hahwul/dalfox/v2@latest
pip install sqlmap

# Other
apt install nikto
```

### Optional (v0.3 new modules)

```bash
# TLS assessment
git clone https://github.com/drwetter/testssl.sh
chmod +x testssl.sh/testssl.sh
# set testssl_path in red_plan.json or ensure testssl.sh is on PATH
# openssl fallback works without testssl.sh

# Directory brute-force
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
# built-in probe (~50 critical paths) runs without either tool
```

### Python dependencies

```bash
pip install httpx asyncio aiofiles
```

## Configuration

All scan parameters live in `assets/red_plan.json`. Key fields:

```json
{
  "domain": "sec-test.skycloud.tw",
  "base_url": "http://sec-test.skycloud.tw",
  "cdn_origin_ip": "38.60.218.193",
  "profiles": {
    "full":          ["recon","wayback","naabu","nuclei","xss","sqli","api_leak","header_check","cors","tls","dirbust","cdn_bypass","nikto"],
    "web-hardening": ["recon","header_check","cors","tls"],
    "discovery":     ["recon","naabu","dirbust"],
    "cdn-test":      ["recon","cors","tls","cdn_bypass","header_check"]
  }
}
```

`cdn_origin_ip` is required for the `cdn_bypass` module's origin-direct test.

## Usage

```bash
# Standard scan using a profile
python main.py --plan assets/red_plan.json --profile web-hardening

# Full pipeline
python main.py --plan assets/red_plan.json --profile full

# CDN-specific tests
python main.py --plan assets/red_plan.json --profile cdn-test

# Resume an interrupted scan
python main.py --plan assets/red_plan.json --resume

# Batch scan from file (one target per line)
python main.py --plan assets/red_plan.json --target-file targets.txt --profile full

# Single module run
python main.py --plan assets/red_plan.json --modules cors,tls

# Specify output directory
python main.py --plan assets/red_plan.json --profile full --output-dir output/june-run
```

### resume.cfg format

```
target=sec-test.skycloud.tw
output_dir=output/sec-test.skycloud.tw/20260622_123456
completed_modules=recon,wayback,naabu
```

`resume.cfg` is written after each module and cleared after a fully successful run.

### targets.txt format

```
# SkyCloud web assets
sec-test.skycloud.tw
api.skycloud.com.tw
# staging.skycloud.tw  (commented out)
```

## Output

Each scan produces a timestamped directory under `output/<target>/<datetime>/`:

```
output/sec-test.skycloud.tw/20260622_143022/
├── report.html      full report with CVSS column (open in browser)
├── report.json      structured data for automation / diff
├── report.md        Markdown summary
├── surface.json     attack surface data (domains, ports, URLs, params)
├── subdomains.txt   discovered hostnames
├── crawled_urls.txt URLs from xcrawl3r/fallback crawler
└── wayback_gau_urls.txt  historical URLs
```

Compare two runs for regressions:
```bash
python scan_diff.py output/sec-test.skycloud.tw/old/report.json \
                    output/sec-test.skycloud.tw/new/report.json \
                    --output diff.json
```

## CVSS scoring reference (v0.3 modules)

| Finding | Severity | CVSS v3.1 |
|---------|----------|-----------|
| Credentialed CORS | Critical | 9.1 |
| .env / .git / web.config exposed | Critical | 9.1 |
| Origin server bypasses CDN | High | 7.5 |
| Arbitrary CORS origin reflection | High | 7.5 |
| Host header injection | High | 7.5 |
| Expired TLS certificate | High | 8.2 |
| TLS 1.0 / 1.1 accepted | Medium | 5.9 |
| IP spoofing header accepted | Medium | 5.3 |
| CORS wildcard (no credentials) | Medium | 5.3 |
| Cache-Control missing on cookies | Medium | 5.3 |
| Admin panel exposed | High | 7.5 |
| Backup file exposed | High | 8.2 |

## Methodology frameworks

- MITRE ATT&CK (Enterprise + Cloud + Recon)
- PTES — Penetration Testing Execution Standard
- OWASP Web Security Testing Guide (WSTG)
- NIST SP 800-115 — Technical Guide for Security Testing
