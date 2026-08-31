# ============================================================
# modules/http_methods_scanner.py — HTTP method audit
# Maps to: OWASP WSTG-CONF-06 (Test HTTP Methods)
# ============================================================
#
# Enumerates the HTTP methods a host accepts and flags dangerous ones.
# Uses curl only — no extra tool dependency.
#
# Checks performed per host root:
#   1. OPTIONS — read the advertised Allow / Access-Control-Allow-Methods list
#   2. TRACE   — active probe for Cross-Site Tracing (XST); confirmed only when
#                the server actually answers 200 and echoes the request back
#   3. PUT / DELETE / PATCH / CONNECT — flagged when advertised as allowed
# ============================================================

from __future__ import annotations

import logging

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

_CVSS: dict[str, float] = {
    "critical": 9.1,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

# method → (severity, vuln_type, description, remediation) when advertised as allowed.
# TRACE is handled separately because it is only reported after active confirmation.
_DANGEROUS_METHODS: dict[str, tuple[str, str, str, str]] = {
    "PUT": (
        "high",
        "http_method_put",
        "Server advertises the PUT method. If write access is not tightly restricted, "
        "an attacker may upload arbitrary files (e.g. a web shell) to the document root, "
        "leading to remote code execution.",
        "Disable PUT unless a REST endpoint genuinely requires it; when required, enforce "
        "authentication, authorisation, and a strict upload path/content-type allowlist.",
    ),
    "DELETE": (
        "high",
        "http_method_delete",
        "Server advertises the DELETE method. If not restricted, an attacker may remove "
        "server-side resources, causing data loss or denial of service.",
        "Disable DELETE at the web server unless required by an authenticated REST API.",
    ),
    "CONNECT": (
        "medium",
        "http_method_connect",
        "Server advertises the CONNECT method, which can turn the host into an open proxy "
        "and allow attackers to tunnel traffic to internal or third-party systems.",
        "Disable the CONNECT method on the web server / reverse proxy.",
    ),
    "PATCH": (
        "low",
        "http_method_patch",
        "Server advertises the PATCH method — partial-modification requests are accepted. "
        "Review whether unauthenticated clients should be able to modify resources.",
        "Disable PATCH unless an authenticated REST endpoint requires it.",
    ),
}

# Methods considered normal/expected — never flagged on their own.
_SAFE_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}


class HTTPMethodsScanner:
    """Audits the HTTP methods accepted by each host (WSTG-CONF-06)."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen_hosts: set[str] = set()
        for target in targets:
            url = target if target.startswith("http") else f"http://{target}"
            if url in seen_hosts:
                continue
            seen_hosts.add(url)
            vulns.extend(await self._audit(url))
        log.info("HTTP methods scanner reported %s findings", len(vulns))
        return vulns

    async def _audit(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        allowed = await self._advertised_methods(url)
        if allowed:
            for method in sorted(allowed):
                if method in _DANGEROUS_METHODS:
                    severity, vtype, desc, remed = _DANGEROUS_METHODS[method]
                    vulns.append(Vulnerability(
                        vuln_type=vtype,
                        severity=severity,
                        url=url,
                        parameter=method,
                        description=desc,
                        remediation=remed,
                        evidence=f"OPTIONS {url} → Allow: {', '.join(sorted(allowed))}",
                        tool="http_methods_scanner",
                        cvss_score=_CVSS[severity],
                    ))

            uncommon = sorted(m for m in allowed if m not in _SAFE_METHODS and m not in _DANGEROUS_METHODS and m != "TRACE")
            if uncommon:
                vulns.append(Vulnerability(
                    vuln_type="http_method_uncommon",
                    severity="info",
                    url=url,
                    parameter=", ".join(uncommon),
                    description=(
                        "Server advertises non-standard HTTP methods. Review whether these are "
                        "intentional and properly access-controlled."
                    ),
                    remediation="Restrict the accepted method set to those the application requires.",
                    evidence=f"OPTIONS {url} → Allow: {', '.join(sorted(allowed))}",
                    tool="http_methods_scanner",
                    cvss_score=_CVSS["info"],
                ))

        # TRACE is only reported when the server actually answers it — an
        # advertised-but-blocked TRACE is not exploitable, so we confirm with
        # an active probe rather than trusting the Allow header alone.
        xst = await self._probe_trace(url)
        if xst is not None:
            vulns.append(xst)

        return vulns

    async def _advertised_methods(self, url: str) -> set[str]:
        """Read Allow / Access-Control-Allow-Methods from an OPTIONS response."""
        status, headers, _ = await self._request("OPTIONS", url)
        if status is None:
            log.warning("http_methods: OPTIONS request failed for %s", url)
            return set()

        methods: set[str] = set()
        for header_name in ("allow", "access-control-allow-methods"):
            raw = headers.get(header_name, "")
            for token in raw.replace(";", ",").split(","):
                token = token.strip().upper()
                if token:
                    methods.add(token)
        return methods

    async def _probe_trace(self, url: str) -> Vulnerability | None:
        """Actively confirm TRACE (Cross-Site Tracing / XST)."""
        status, _, body = await self._request("TRACE", url)
        if status != 200:
            return None
        # A genuine TRACE response echoes the request; the method name in the
        # returned body is the reliable tell.
        if "TRACE" not in body.upper():
            return None
        return Vulnerability(
            vuln_type="http_method_trace",
            severity="medium",
            url=url,
            parameter="TRACE",
            description=(
                "The TRACE method is enabled and the server echoes the request back "
                "(Cross-Site Tracing / XST). Combined with another flaw, this can be used "
                "to read headers such as cookies or Authorization that are otherwise "
                "protected by HttpOnly."
            ),
            remediation="Disable the TRACE method on the web server (e.g. nginx: return 405 for TRACE).",
            evidence=f"TRACE {url} → HTTP 200 with request echoed in body",
            tool="http_methods_scanner",
            cvss_score=_CVSS["medium"],
        )

    async def _request(self, method: str, url: str) -> tuple[int | None, dict[str, str], str]:
        """Send one request with an explicit method; return (status, headers, body)."""
        result = await run_tool(
            ["curl", "-s", "-i", "-X", method, "-L",
             "--max-time", str(self.config.timeout),
             "-A", "Mozilla/5.0", url],
            timeout=self.config.timeout + 5,
        )
        out = result["stdout"]
        if not out:
            return None, {}, ""
        return self._parse_response(out)

    @staticmethod
    def _parse_response(raw: str) -> tuple[int | None, dict[str, str], str]:
        """Split a curl -i response into (status_code, headers, body).

        Follows the last header block so redirects (curl -L) resolve to the
        final response's status and headers.
        """
        head, _, body = raw.partition("\r\n\r\n")
        if not body and "\n\n" in raw:
            head, _, body = raw.partition("\n\n")

        # With -L there may be several header blocks; keep the final one.
        blocks = head.replace("\r\n", "\n").split("\n\n")
        last = blocks[-1] if blocks else head

        status: int | None = None
        headers: dict[str, str] = {}
        for line in last.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.upper().startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status = int(parts[1])
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return status, headers, body
