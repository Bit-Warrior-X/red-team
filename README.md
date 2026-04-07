# RedScanner

RedScanner is a Python orchestrator that chains external security tools into a single pipeline: reconnaissance, historical URL discovery, port scanning, template-based scanning, XSS/SQLi checks, JS secret pattern matching, and reporting. Engagement defaults and profiles live in **`assets/red_plan.json`**.

Use only on systems you are authorized to test.

## Requirements

- **Python** 3.10+ (uses `asyncio`, type unions)
- Optional **CLI tools** on `PATH` (missing tools are skipped; the log lists what was found):

  | Role | Typical binary |
  |------|----------------|
  | Subdomains / HTTP | `subfinder`, `httpx`, `assetfinder` |
  | Crawl | `xcrawl3r` (see note below) |
  | Historical URLs | `waybackurls`, `gau` |
  | Ports | `naabu` |
  | Scanning | `nuclei`, `nikto` |
  | App testing | `dalfox`, `sqlmap` |
  | Fetch | `curl` (fallback when `xcrawl3r` is absent) |

Install tools from their upstream projects (e.g. ProjectDiscovery, PortSwigger docs for Burp are separate—Burp is not invoked by this script).

### xcrawl3r

This project runs **`xcrawl3r -u <url>`** only. In xcrawl3r v1.2+, **`-d` / `--domain` is for scope**, not crawl depth; depth is **`--depth`**. RedScanner does not pass `-d` for depth.

## Quick start

```bash
cd /home/red
python3 -m venv venv
source venv/bin/activate
# Install dependencies if you add a requirements.txt; the orchestrator uses mostly stdlib.
```

Edit **`assets/red_plan.json`** if you need another default **`domain`** or **`base_url`**.

```bash
# List profiles (built-in + merged from red_plan.json)
python main.py --list-profiles

# Full pipeline (default profile: full)
python main.py

# Explicit profile
python main.py --profile lite

# Another target
python main.py -t example.com --profile quick
```

## Configuration

- **`assets/red_plan.json`** — Default `domain`, `base_url`, `profiles`, `manual_phases`, `methodology_frameworks`, `research_references`, and `title` / `description` for reports.
- **`--plan-file`** — Point to an alternate JSON with the same shape.

If **`domain`** is set in the plan file, **`--target`** (`-t`) can be omitted.

## Command-line reference

```
python main.py [-h] [-t TARGET] [--plan-file PATH] [-p PROFILE] [-m MODULES]
               [-o OUTPUT] [--threads N] [--timeout SEC] [--rate-limit N]
               [--list-profiles] [--max-wayback N] [--max-deep N]
```

| Option | Description |
|--------|-------------|
| `-t`, `--target` | Target hostname (default: `domain` in `red_plan.json`) |
| `--plan-file` | Engagement JSON (default: `assets/red_plan.json`) |
| `-p`, `--profile` | Profile name (default: **`full`**) |
| `-m`, `--modules` | Comma-separated modules; **overrides** `--profile` |
| `-o`, `--output` | Output root directory (default: `./output`) |
| `--threads` | Concurrency where supported (default: 10) |
| `--timeout` | HTTP / tool timeout in seconds (default: 30) |
| `--rate-limit` | Nuclei requests per second (default: 50) |
| `--max-wayback` | Cap URLs from wayback/gau (default: 500) |
| `--max-deep` | Max URLs for dalfox, sqlmap, api_leak (default: 25; nuclei uses full surface) |
| `--list-profiles` | Print profiles and exit |

## Profiles and modules

Modules run in this order when selected: **`recon`** → **`wayback`** → **`naabu`** → **`nuclei`** → **`xss`** → **`sqli`** → **`api_leak`** → **`nikto`**.

Built-in profiles include:

| Profile | Typical use |
|---------|-------------|
| `full` | All modules above |
| `lite` | `recon`, `nuclei`, `xss`, `sqli`, `api_leak` |
| `red-team` | Same as `full` in code |
| `recon-only`, `quick`, `vuln-only` | As named |

Additional profiles may be defined under **`profiles`** in **`assets/red_plan.json`**.

## Output

Each run writes a timestamped directory:

`output/<target>/<YYYYMMDD_HHMMSS>/`

| Artifact | Purpose |
|----------|---------|
| `report.html` / `report.md` | Human-readable report with attack-surface tables |
| `report.json` | Full run + `surface` (domains, URLs, ports, assets, parameters) |
| `surface.json` | Same `surface` object only |
| `results.db` | SQLite with assets and vulnerabilities |
| `recon/` | `subdomains.txt`, `crawled_urls.txt`, naabu files, etc. |
| `sqlmap/`, `nikto/` | Tool output when those modules ran |

Logs also append to **`redscanner.log`** in the project root.

## Project layout

```
main.py
assets/red_plan.json
core/          # config, db, models, tool runner, surface helpers, plan loader
modules/       # recon, scanners, report generator
```

## Legal

Only use RedScanner against targets you own or have **explicit written permission** to assess. Unauthorized scanning may violate law; you are responsible for compliance.
