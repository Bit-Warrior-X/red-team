# RedScanner v0.3.1

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

## v0.3.1 — wiring &amp; resume fixes

The v0.3 modules above (`cors`, `tls`, `dirbust`, `cdn_bypass`) and the
`--resume` / `--target-file` flags were implemented but never actually wired
into `main.py` — running any v0.3 profile silently skipped them with an
"Unknown module skipped" warning, and `--resume`/`--target-file` didn't exist
as CLI flags at all. This pass fixes that:

| Fix | Details |
|-----|---------|
| Module wiring | `cors`, `tls`, `dirbust`, `cdn_bypass` are now imported, ordered, and dispatched by `main.py`; `full`/`red-team` profiles run all 13 modules end to end |
| `--resume` implemented | Reads/writes `resume.cfg` next to `main.py`; restores recon/wayback state from output files and per-module findings from `results.db` instead of re-running completed modules |
| `--target-file` implemented | Batch-scans a newline-delimited target list sequentially, one output directory per target |
| Incremental result persistence | Findings are now written to `results.db` after each module (tagged with a new `module` column), not just once at the very end — so an interrupted run leaves an accurate on-disk record for `--resume` |
| Dirbust false-positive fix | `.env` / `.git` / config paths that return `HTTP 403` (access denied) were being reported as **critical — sensitive file exposed**; a 403 means the server correctly blocked the request, so this is now `low — sensitive_path_blocked` |
| `--resume` base URL fix | `resume.cfg` now stores the resolved `base_url`, so resuming without repeating `--base-url` no longer silently re-resolves to a different URL (was flipping `https://` → `http://` in testing) |
| `--plan` / `--plan-file` | Both flags now work (the README always documented `--plan`, the code only accepted `--plan-file`) |

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
python main.py --plan assets/red_plan.json --profile full --output output/june-run
```

### resume.cfg format

`resume.cfg` lives next to `main.py` (not inside the per-scan output directory,
since `--resume` needs to find it before it knows which output directory to
use). It is rewritten after every completed module and deleted once the scan
finishes successfully:

```
target=sec-test.skycloud.tw
output_dir=output/sec-test.skycloud.tw/20260622_123456
scan_id=20260622_123456
base_url=https://sec-test.skycloud.tw
modules=recon,wayback,naabu,nuclei,xss,sqli,api_leak,header_check,cors,tls,dirbust,cdn_bypass,nikto
completed_modules=recon,wayback,naabu
```

`--resume` reuses the stored `scan_id`, `output_dir`, `base_url`, and full
`modules` list, so a bare `python main.py --resume` continues the interrupted
scan exactly as it was invoked — you don't need to re-pass `--profile` or
`--base-url`. Passing an explicit `--profile`/`--modules` or `--base-url` on
the resume command overrides the stored value.

**Known limitation:** only `target`, `output_dir`, `scan_id`, `base_url`, and
the module list are persisted. Other tuning flags from the original
invocation (`--threads`, `--timeout`, `--rate-limit`, `--max-deep`,
`--max-wayback`, `--strict-domain`, `--no-header-check`) are *not* stored —
repeat them on the `--resume` command if the original run used non-default
values.

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
| Sensitive path exists but blocked (403 on .env/.git/etc.) | Low | 3.1 |

## Methodology frameworks

- MITRE ATT&CK (Enterprise + Cloud + Recon)
- PTES — Penetration Testing Execution Standard
- OWASP Web Security Testing Guide (WSTG)
- NIST SP 800-115 — Technical Guide for Security Testing
