# ============================================================
# modules/header_scanner.py — HTTP security header analysis
# ============================================================
#
# Checks responses for missing or misconfigured security headers.
# Maps to OWASP WSTG-CONF-07 (Test HTTP Strict Transport Security)
# and WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces).
#
# Runs curl HEAD against each target and evaluates headers against
# a baseline of commonly recommended security headers.
# ============================================================

from __future__ import annotations

import logging
import re

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

# Headers to check: (header_name, severity_if_missing, description, remediation)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "medium",
        "Missing HSTS header — browsers will not enforce HTTPS, allowing downgrade attacks (WSTG-CONF-07)",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    (
        "Content-Security-Policy",
        "medium",
        "Missing Content-Security-Policy header — increases risk of XSS and data injection attacks",
        "Define a CSP policy restricting script, style, and object sources to trusted origins",
    ),
    (
        "X-Content-Type-Options",
        "low",
        "Missing X-Content-Type-Options header — browser may MIME-sniff responses, enabling content-type confusion attacks",
        "Add X-Content-Type-Options: nosniff",
    ),
    (
        "X-Frame-Options",
        "low",
        "Missing X-Frame-Options header — page may be embedded in iframes, enabling clickjacking",
        "Add X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors)",
    ),
    (
        "Referrer-Policy",
        "low",
        "Missing Referrer-Policy header — full URLs may leak in Referer headers to third parties",
        "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
    ),
    (
        "Permissions-Policy",
        "low",
        "Missing Permissions-Policy header — browser features (camera, mic, geolocation) not explicitly restricted",
        "Add Permissions-Policy to disable unnecessary browser features",
    ),
    (
        "X-XSS-Protection",
        "info",
        "Missing X-XSS-Protection header — legacy browsers lack XSS auditor hint (modern browsers deprecated this, CSP preferred)",
        "Add X-XSS-Protection: 0 (disable flawed auditor) and rely on CSP instead",
    ),
]

# Headers that should NOT be present (information disclosure)
DISCLOSURE_HEADERS = [
    (
        "Server",
        "info",
        "Server header discloses web server software/version — aids attacker fingerprinting",
        "Remove or genericize the Server header in web server configuration",
    ),
    (
        "X-Powered-By",
        "info",
        "X-Powered-By header discloses application framework — aids attacker fingerprinting",
        "Remove X-Powered-By header in application or web server configuration",
    ),
    (
        "X-AspNet-Version",
        "low",
        "X-AspNet-Version header discloses .NET runtime version — aids targeted exploitation",
        "Remove X-AspNet-Version via web.config or server configuration",
    ),
]

HEADER_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.+)$")


class HeaderScanner:
    """Checks HTTP response headers against security best practices."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for target in targets:
            url = target if target.startswith("http") else f"http://{target}"
            headers = await self._fetch_headers(url)
            if headers is None:
                log.warning("header_check: could not fetch headers for %s", url)
                continue

            header_lower = {k.lower(): v for k, v in headers.items()}

            # Check for missing security headers
            for name, severity, desc, remed in SECURITY_HEADERS:
                if name.lower() not in header_lower:
                    vulns.append(Vulnerability(
                        vuln_type="missing_security_header",
                        severity=severity,
                        url=url,
                        parameter=name,
                        description=desc,
                        remediation=remed,
                        evidence=f"Header '{name}' not found in response",
                        tool="header_scanner",
                    ))

            # Check for disclosure headers that should be removed
            for name, severity, desc, remed in DISCLOSURE_HEADERS:
                if name.lower() in header_lower:
                    value = header_lower[name.lower()]
                    vulns.append(Vulnerability(
                        vuln_type="header_disclosure",
                        severity=severity,
                        url=url,
                        parameter=name,
                        description=desc,
                        remediation=remed,
                        evidence=f"{name}: {value[:200]}",
                        tool="header_scanner",
                    ))

            # Check for insecure cookie flags on Set-Cookie headers
            vulns.extend(self._check_cookies(url, headers))

        log.info("Header scanner reported %s findings", len(vulns))
        return vulns

    async def _fetch_headers(self, url: str) -> dict[str, str] | None:
        """Fetch headers via curl -I (HEAD request)."""
        result = await run_tool(
            ["curl", "-s", "-I", "-L", "--max-time", "10",
             "-A", "Mozilla/5.0", url],
            timeout=15,
        )
        if not result["stdout"]:
            return None
        headers: dict[str, str] = {}
        for line in result["stdout"].splitlines():
            m = HEADER_RE.match(line.strip())
            if m:
                headers[m.group(1)] = m.group(2).strip()
        return headers if headers else None

    def _check_cookies(self, url: str, headers: dict[str, str]) -> list[Vulnerability]:
        """Check Set-Cookie headers for missing Secure, HttpOnly, SameSite flags."""
        vulns: list[Vulnerability] = []
        for name, value in headers.items():
            if name.lower() != "set-cookie":
                continue
            cookie_name = value.split("=")[0].strip() if "=" in value else "unknown"
            lower_val = value.lower()

            if url.startswith("https://") and "secure" not in lower_val:
                vulns.append(Vulnerability(
                    vuln_type="insecure_cookie",
                    severity="low",
                    url=url,
                    parameter=cookie_name,
                    description=f"Cookie '{cookie_name}' missing Secure flag — may be sent over unencrypted HTTP",
                    remediation="Add Secure flag to Set-Cookie header",
                    evidence=f"Set-Cookie: {value[:300]}",
                    tool="header_scanner",
                ))
            if "httponly" not in lower_val:
                vulns.append(Vulnerability(
                    vuln_type="insecure_cookie",
                    severity="low",
                    url=url,
                    parameter=cookie_name,
                    description=f"Cookie '{cookie_name}' missing HttpOnly flag — accessible to JavaScript (XSS risk)",
                    remediation="Add HttpOnly flag to Set-Cookie header",
                    evidence=f"Set-Cookie: {value[:300]}",
                    tool="header_scanner",
                ))
            if "samesite" not in lower_val:
                vulns.append(Vulnerability(
                    vuln_type="insecure_cookie",
                    severity="info",
                    url=url,
                    parameter=cookie_name,
                    description=f"Cookie '{cookie_name}' missing SameSite attribute — may be sent in cross-site requests (CSRF risk)",
                    remediation="Add SameSite=Lax or SameSite=Strict to Set-Cookie header",
                    evidence=f"Set-Cookie: {value[:300]}",
                    tool="header_scanner",
                ))
        return vulns