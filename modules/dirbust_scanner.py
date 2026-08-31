# ============================================================
# modules/dirbust_scanner.py — Directory and file enumeration
# Maps to: OWASP WSTG-CONF-05 (Enumerate Infrastructure and
#          Application Admin Interfaces)
# Tools: gobuster (preferred), ffuf (alternative), curl built-in fallback
# ============================================================

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

_CVSS: dict[str, float] = {
    "critical": 9.1,
    "high": 8.2,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

# Common wordlist locations (tried in order). Bundled SecLists merge first.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_WORDLISTS = [
    os.path.join(_REPO_ROOT, "assets", "wordlists", "all.txt"),
    os.path.join(_REPO_ROOT, "assets", "wordlists", "common.txt"),
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

# Paths probed when no external tool / wordlist is available
BUILTIN_PATHS = [
    # Admin / management interfaces
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/login", "/admin/login.php",
    "/manager", "/manager/", "/console", "/console/",
    "/panel", "/panel/", "/dashboard", "/dashboard/",
    "/controlpanel", "/control", "/backend",
    # Authentication
    "/login", "/login.php", "/signin", "/auth",
    # Sensitive files — secrets / source
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git", "/.git/config", "/.git/HEAD",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/config.inc.php",
    "/configuration.php", "/settings.php", "/database.php",
    "/app.config", "/appsettings.json",
    # Backups
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql", "/db_backup.sql",
    "/site.tar.gz", "/site.zip", "/www.zip",
    # Debug / info disclosure
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info",
    "/debug", "/debug/", "/test", "/dev", "/staging",
    # Spring Boot / Node actuators
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/health", "/healthz", "/status", "/metrics", "/prometheus",
    # API endpoints
    "/api", "/api/v1", "/api/v2",
    "/api/v1/users", "/api/v1/admin", "/api/v1/config",
    # Upload / files
    "/upload", "/uploads", "/files", "/static", "/assets",
    # Common files
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt",
]

# HTTP statuses that count as "found" (not just 200)
_FOUND_STATUSES = {200, 204, 301, 302, 307, 401, 403}

# Paths/extensions that are high-value findings
_CRITICAL_PATTERNS = [
    r"/\.env",
    r"/\.git",
    r"/web\.config",
    r"wp-config\.php",
    r"settings\.php",
    r"config\.php",
    r"appsettings\.json",
]
_HIGH_ADMIN = ["/admin", "/administrator", "/manager", "/console", "/panel", "/dashboard", "/controlpanel", "/backend"]
_HIGH_BACKUP = [".zip", ".tar.gz", ".sql", ".bak", ".dump", ".tar"]
_MEDIUM_DEBUG = [
    "/debug", "/test", "/dev", "/staging", "/phpinfo", "/info.php",
    "/server-status", "/actuator",
    # Monitoring / metrics endpoints (often unauthenticated info disclosure)
    "/metrics", "/prometheus", "/health", "/healthz", "/status",
]

# Strip ANSI / progress-control codes gobuster v2 emits even with -q/-np
_ANSI_RE = re.compile(r"(?:\x1b\[[0-9;]*[A-Za-z]|\r)")


def _classify(path: str, status: int) -> tuple[str, float, str]:
    """Return (severity, cvss_score, vuln_type) for a discovered path."""
    p = path.lower()

    if status not in _FOUND_STATUSES:
        return "info", 0.0, "path_probed"

    for pattern in _CRITICAL_PATTERNS:
        if re.search(pattern, p):
            if status in (200, 204, 301, 302, 307):
                return "critical", _CVSS["critical"], "sensitive_file_exposed"
            if status in (401, 403):
                # Server actively denied access — the path exists (worth
                # noting) but this is the secure outcome, not an exposure.
                # (Previously misclassified as "critical" for any of
                # _FOUND_STATUSES, which flagged correctly-blocked .env/.git
                # paths as if the secrets were actually served.)
                return "low", 3.1, "sensitive_path_blocked"

    for prefix in _HIGH_ADMIN:
        if p.startswith(prefix):
            if status in (200, 301, 302, 307):
                return "high", 7.5, "admin_interface_found"
            if status == 403:
                return "medium", 5.3, "admin_interface_forbidden"

    for ext in _HIGH_BACKUP:
        if p.endswith(ext) and status == 200:
            return "high", _CVSS["high"], "backup_file_found"

    for prefix in _MEDIUM_DEBUG:
        if p.startswith(prefix) and status in (200, 301, 302, 307):
            return "medium", _CVSS["medium"], "debug_endpoint_found"

    if status in (200, 301, 302, 307):
        return "low", _CVSS["low"], "interesting_path_found"

    return "info", _CVSS["info"], "path_accessible"


def _remediation(path: str, vuln_type: str) -> str:
    p = path.lower()
    if ".env" in p or ".git" in p:
        return (
            "Immediately block access: add 'location ~ /\\. { deny all; }' in nginx.conf. "
            "Rotate any secrets that may have been exposed."
        )
    if "admin" in p or "manager" in p or "console" in p:
        return (
            "Restrict admin interfaces by IP allowlist or VPN. "
            "Enable multi-factor authentication on all admin accounts."
        )
    if any(ext in p for ext in [".zip", ".sql", ".bak", ".tar", ".dump"]):
        return (
            "Delete backup and database dump files from the web root. "
            "Store backups outside the document root or on a separate, access-controlled storage."
        )
    if "phpinfo" in p or "server-status" in p:
        return "Disable phpinfo pages and server-status in the production nginx/PHP config."
    if "debug" in p or "actuator" in p or "metrics" in p or "prometheus" in p:
        return (
            "Disable or restrict management, metrics, and actuator endpoints in production. "
            "Apply IP filtering or authentication; do not expose Prometheus/metrics scrapers publicly."
        )
    return "Review this path and remove or restrict access if not required for normal operation."


def _gobuster_is_v3(gobuster_path: str) -> bool:
    """gobuster v3+ uses subcommands (`gobuster dir`); v1/v2 use `-m dir`."""
    try:
        import subprocess
        proc = subprocess.run(
            [gobuster_path, "-h"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        # Classic v1/v2 help lists the -m mode flag.
        if re.search(r"(?m)^\s*-m\s", out) or "Directory/File mode (dir)" in out:
            return False
        if "Available Commands" in out or "gobuster dir" in out:
            return True
    except Exception:
        pass
    # Prefer v3-style CLI when unsure (most current installs).
    return True


# Wordlists at/above this size skip -x extensions (each extension multiplies
# requests). Prefer common.txt when the configured list is huge (all.txt).
_LARGE_WORDLIST_LINES = 8_000
_SKIP_EXTENSIONS_LINES = 2_000
# Wall-clock budget for gobuster/ffuf in a full profile (builtin probe is separate).
_DIRBUST_TOOL_TIMEOUT = 150


class DirbustScanner:
    """
    Enumerates directories and files on HTTP targets.
    Order: built-in high-value probe first (fast), then gobuster/ffuf.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for url in targets:
            base = url.rstrip("/")

            # Built-in probe first — finds /metrics, /.env, etc. in seconds
            # instead of waiting behind a multi-minute gobuster run.
            builtin_vulns = await self._builtin_probe(base)

            tool_vulns: list[Vulnerability] = []
            if shutil.which(self.config.gobuster_path):
                tool_vulns = await self._gobuster(base)
            elif shutil.which(self.config.ffuf_path):
                tool_vulns = await self._ffuf(base)
            else:
                log.info(
                    "dirbust: gobuster/ffuf not on PATH — built-in path list only "
                    "(install gobuster for broader enumeration)"
                )

            vulns.extend(self._merge_vulns(tool_vulns, builtin_vulns))
        log.info("Dirbust scanner reported %s findings", len(vulns))
        return vulns

    @staticmethod
    def _merge_vulns(primary: list[Vulnerability], secondary: list[Vulnerability]) -> list[Vulnerability]:
        """Dedup by (url, path/parameter); keep the higher-severity hit."""
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        best: dict[tuple[str, str], Vulnerability] = {}
        for v in primary + secondary:
            key = (v.url, v.parameter or "")
            prev = best.get(key)
            if prev is None or rank.get(v.severity, 5) < rank.get(prev.severity, 5):
                best[key] = v
        return list(best.values())

    @staticmethod
    def _count_lines(path: str) -> int:
        try:
            with open(path, "rb") as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    def _select_wordlist(self) -> tuple[str | None, bool]:
        """Return (wordlist_path, use_extensions).

        Huge lists (e.g. all.txt ~165k) × 6 extensions ≈ 1M requests — that
        timed out at 600s with zero usable output. Prefer common.txt when the
        configured list is oversized, and skip -x on large lists.
        """
        wordlist = self._find_wordlist()
        if not wordlist:
            return None, False

        lines = self._count_lines(wordlist)
        use_ext = lines < _SKIP_EXTENSIONS_LINES
        if lines >= _LARGE_WORDLIST_LINES:
            common = os.path.join(_REPO_ROOT, "assets", "wordlists", "common.txt")
            sibling = os.path.join(os.path.dirname(wordlist), "common.txt")
            for candidate in (common, sibling):
                if os.path.abspath(candidate) != os.path.abspath(wordlist) and os.path.exists(candidate):
                    log.warning(
                        "dirbust: wordlist %s has %s lines — using %s for full-profile speed "
                        "(keep all.txt only for dedicated deep discovery runs)",
                        wordlist, lines, candidate,
                    )
                    # common.txt is still above _SKIP_EXTENSIONS_LINES → no -x
                    return candidate, False
            log.warning(
                "dirbust: wordlist %s has %s lines — skipping -x extensions to reduce request volume",
                wordlist, lines,
            )
            return wordlist, False
        if not use_ext:
            log.info(
                "dirbust: wordlist has %s lines — skipping -x extensions (use a smaller list to enable them)",
                lines,
            )
        return wordlist, use_ext

    # ── gobuster ─────────────────────────────────────────────

    async def _gobuster(self, base_url: str) -> list[Vulnerability]:
        wordlist, use_ext = self._select_wordlist()
        if not wordlist:
            log.warning("dirbust: no wordlist found — gobuster skipped (built-in probe already ran)")
            return []

        ext = ""
        if use_ext:
            ext = ",".join(self.config.dirbust_extensions) if self.config.dirbust_extensions else "php,html,txt,bak,zip,sql"

        wall = _DIRBUST_TOOL_TIMEOUT
        log.info(
            "dirbust: gobuster wordlist=%s extensions=%s timeout=%ss",
            wordlist, ext or "(none)", wall,
        )

        threads = min(max(self.config.threads, 10), 30)
        v3 = _gobuster_is_v3(self.config.gobuster_path)
        if v3:
            cmd = [
                self.config.gobuster_path, "dir",
                "-u", base_url,
                "-w", wordlist,
                "-q", "--no-progress",
                "-t", str(threads),
                "--timeout", f"{min(self.config.timeout, 10)}s",
                "-s", "200,204,301,302,307,401,403",
            ]
            if ext:
                cmd.extend(["-x", ext])
        else:
            log.info("dirbust: detected gobuster v2-style CLI — using -m dir")
            cmd = [
                self.config.gobuster_path,
                "-m", "dir",
                "-u", base_url,
                "-w", wordlist,
                "-q", "-np",
                "-t", str(threads),
                "-to", f"{min(self.config.timeout, 10)}s",
                "-s", "200,204,301,302,307,401,403",
                "-a", "Mozilla/5.0",
            ]
            if ext:
                cmd.extend(["-x", ext])

        result = await run_tool(cmd, timeout=wall)
        if result["returncode"] not in (0, None) and not result["stdout"].strip():
            log.warning(
                "dirbust: gobuster returned no results (rc=%s) — built-in probe results still kept. stderr: %s",
                result["returncode"],
                (result.get("stderr") or "")[:300],
            )
        return self._parse_gobuster(base_url, result["stdout"])

    def _parse_gobuster(self, base_url: str, stdout: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for raw_line in stdout.splitlines():
            line = _ANSI_RE.sub("", raw_line).strip()
            # Format: /path  (Status: 200) [Size: 1234]
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if not m:
                continue
            path, status = m.group(1), int(m.group(2))
            if status == 404:
                continue
            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                continue
            vulns.append(Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=base_url + path,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status} (gobuster)",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="gobuster",
                cvss_score=cvss,
            ))
        return vulns

    # ── ffuf ──────────────────────────────────────────────────

    async def _ffuf(self, base_url: str) -> list[Vulnerability]:
        wordlist, _use_ext = self._select_wordlist()
        if not wordlist:
            log.warning("dirbust: no wordlist found — ffuf skipped (built-in probe already ran)")
            return []

        wall = _DIRBUST_TOOL_TIMEOUT
        result = await run_tool(
            [
                self.config.ffuf_path,
                "-u", f"{base_url}/FUZZ",
                "-w", wordlist,
                "-mc", "200,204,301,302,307,401,403",
                "-t", str(min(max(self.config.threads, 10), 30)),
                "-s",
                "-of", "json",
            ],
            timeout=wall,
        )
        return self._parse_ffuf(base_url, result["stdout"])

    def _parse_ffuf(self, base_url: str, stdout: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        try:
            import json as _json
            data = _json.loads(stdout)
            results = data.get("results", [])
        except Exception:
            # Fallback: parse plain text output line by line
            results = []
            for line in stdout.splitlines():
                m = re.search(r"(\S+)\s+\[Status:\s*(\d+)", line)
                if m:
                    results.append({"input": {"FUZZ": m.group(1)}, "status": int(m.group(2))})

        for item in results:
            if isinstance(item, dict):
                fuzz_val = item.get("input", {}).get("FUZZ") or item.get("url", "")
                path = "/" + str(fuzz_val).lstrip("/")
                status = int(item.get("status", 0))
            else:
                continue
            if status == 404:
                continue
            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                continue
            vulns.append(Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=base_url + path,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status} (ffuf)",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="ffuf",
                cvss_score=cvss,
            ))
        return vulns

    # ── built-in curl fallback ────────────────────────────────

    async def _builtin_probe(self, base_url: str) -> list[Vulnerability]:
        """Probe BUILTIN_PATHS concurrently with curl (no external wordlist tool)."""
        sem = asyncio.Semaphore(min(20, max(5, self.config.threads)))

        async def _one(path: str) -> Vulnerability | None:
            url = base_url + path
            async with sem:
                result = await run_tool(
                    [
                        "curl", "-s", "-o", "/dev/null",
                        "-w", "%{http_code}",
                        "--max-time", "8",
                        "--max-redirs", "3",
                        "-A", "Mozilla/5.0",
                        url,
                    ],
                    timeout=12,
                    quiet=True,
                )
            status_str = result["stdout"].strip()
            try:
                status = int(status_str)
            except ValueError:
                return None
            if status == 404 or status == 0:
                return None
            sev, cvss, vtype = _classify(path, status)
            if sev not in ("critical", "high", "medium", "low"):
                return None
            return Vulnerability(
                vuln_type=vtype,
                severity=sev,
                url=url,
                parameter=path,
                description=f"Path '{path}' returned HTTP {status}",
                remediation=_remediation(path, vtype),
                evidence=f"GET {path} → HTTP {status}",
                tool="dirbust_scanner",
                cvss_score=cvss,
            )

        log.info("dirbust: built-in probe of %s high-value paths (concurrent)", len(BUILTIN_PATHS))
        results = await asyncio.gather(*[_one(p) for p in BUILTIN_PATHS])
        return [v for v in results if v is not None]

    # ── util ─────────────────────────────────────────────────

    def _find_wordlist(self) -> str | None:
        if self.config.dirbust_wordlist:
            candidate = self.config.dirbust_wordlist
            if not os.path.isabs(candidate):
                # Prefer CWD (usual: repo root), then repo-relative to this module.
                for base in (os.getcwd(), _REPO_ROOT):
                    joined = os.path.join(base, candidate)
                    if os.path.exists(joined):
                        return joined
            if os.path.exists(candidate):
                return candidate
        for path in _WORDLISTS:
            if os.path.exists(path):
                return path
        return None
