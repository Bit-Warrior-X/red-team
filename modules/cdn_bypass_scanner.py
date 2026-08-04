# ============================================================
# modules/cdn_bypass_scanner.py — CDN/WAF bypass and origin exposure
# Maps to: Red Team Plan — CDN & Edge Attacks section
#          OWASP WSTG-CONF-02 (Test Application Platform Configuration)
# ============================================================
#
# Tests performed:
#   1. Direct origin IP access with Host header (CDN bypass)
#   2. IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
#   3. Host header injection → check for reflection in response
#   4. Cache-Control analysis on responses with cookies
#   5. X-Cache-Status presence check (CDN node health)
# ============================================================

from __future__ import annotations

import logging
from urllib.parse import urlparse

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

# Headers that CDN operators often trust for IP identification —
# if the server behaves differently when one is added, IP-based logic is bypassable.
_IP_BYPASS_HEADERS = [
    "X-Forwarded-For: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Originating-IP: 127.0.0.1",
    "True-Client-IP: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "CF-Connecting-IP: 127.0.0.1",
    "Fastly-Client-Ip: 127.0.0.1",
    "X-Cluster-Client-IP: 127.0.0.1",
    "X-Forwarded-For: 0.0.0.0",
    "X-Forwarded-For: ::1",
]


class CDNBypassScanner:
    """
    Probes for CDN/WAF bypass vulnerabilities and CDN misconfiguration.
    Requires cdn_origin_ip in red_plan.json to test direct origin access.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        primary_url = targets[0] if targets else (
            self.config.base_url or f"http://{self.config.target}"
        )

        # Fetch baseline (through CDN)
        baseline = await self._fetch(primary_url)
        baseline_status = baseline["status"]

        # Test 1: direct origin access
        if self.config.cdn_origin_ip:
            vulns.extend(await self._test_origin_direct(primary_url, baseline))

        # Test 2: IP spoofing headers
        vulns.extend(await self._test_ip_headers(primary_url, baseline_status))

        # Test 3: Host header injection
        vulns.extend(await self._test_host_injection(primary_url))

        # Test 4: Cache-Control on Set-Cookie responses
        vulns.extend(await self._test_cache_deception(primary_url))

        # Test 5: CDN health / X-Cache-Status presence
        vulns.extend(await self._test_cdn_health_headers(primary_url))

        log.info("CDN bypass scanner reported %s findings", len(vulns))
        return vulns

    # ── Test 1: direct origin ────────────────────────────────

    async def _test_origin_direct(self, url: str, baseline: dict) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(url)
        host = parsed.hostname or self.config.target
        scheme = parsed.scheme or "http"
        path = parsed.path or "/"

        origin_url = f"{scheme}://{self.config.cdn_origin_ip}{path}"
        result = await self._fetch(origin_url, extra_headers=[f"Host: {host}"])

        status = result["status"]
        if status and status < 500:
            # If origin responds and lacks CDN-specific response headers → exposed
            hdrs = result["headers"]
            cdn_markers = {"x-cache", "x-cache-status", "cf-ray", "x-amz-cf-id", "x-cdn", "via"}
            found_cdn = any(m in hdrs for m in cdn_markers)

            if not found_cdn:
                vulns.append(Vulnerability(
                    vuln_type="cdn_origin_exposed",
                    severity="high",
                    url=origin_url,
                    parameter="Host",
                    description=(
                        f"Origin server ({self.config.cdn_origin_ip}) responds directly when "
                        f"addressed with Host: {host}. Attackers can bypass the CDN/WAF entirely by "
                        "sending requests directly to the origin IP, bypassing DDoS protection, "
                        "WAF rules, and rate limiting."
                    ),
                    remediation=(
                        "Restrict the origin web server to only accept connections from the CDN node's "
                        "IP range using firewall rules (iptables/nftables/CSF). "
                        "Verify with: iptables -A INPUT -p tcp --dport 80 -s <cdn_ip> -j ACCEPT; "
                        "iptables -A INPUT -p tcp --dport 80 -j DROP"
                    ),
                    evidence=(
                        f"Direct GET {self.config.cdn_origin_ip} with Host: {host} → HTTP {status} "
                        f"(no CDN headers in response)"
                    ),
                    tool="cdn_bypass_scanner",
                    cvss_score=_CVSS["high"],
                ))
        return vulns

    # ── Test 2: IP header spoofing ────────────────────────────

    async def _test_ip_headers(self, url: str, baseline_status: int | None) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for header in _IP_BYPASS_HEADERS:
            result = await self._fetch(url, extra_headers=[header])
            status = result["status"]
            if status and baseline_status and status != baseline_status:
                hdr_name = header.split(":")[0]
                vulns.append(Vulnerability(
                    vuln_type="cdn_ip_header_bypass",
                    severity="medium",
                    url=url,
                    parameter=hdr_name,
                    description=(
                        f"Adding '{header}' changed the server response from HTTP {baseline_status} "
                        f"to HTTP {status}. The CDN or origin server trusts this header for IP-based "
                        "access control, which can be spoofed by any client."
                    ),
                    remediation=(
                        "Do not use X-Forwarded-For or similar headers for security decisions unless "
                        "they originate from a trusted, internal proxy. "
                        "Strip or validate these headers at the CDN edge before forwarding to origin."
                    ),
                    evidence=f"Baseline HTTP {baseline_status} | With '{header}': HTTP {status}",
                    tool="cdn_bypass_scanner",
                    cvss_score=_CVSS["medium"],
                ))
        return vulns

    # ── Test 3: Host header injection ────────────────────────

    async def _test_host_injection(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        injected_host = "evil-canary-host.example.com"
        result = await self._fetch(url, extra_headers=[f"Host: {injected_host}"])

        raw_lower = (result["raw"] or "").lower()
        if injected_host.lower() in raw_lower:
            vulns.append(Vulnerability(
                vuln_type="host_header_injection",
                severity="high",
                url=url,
                parameter="Host",
                description=(
                    f"Server reflects the injected Host header value '{injected_host}' in its response. "
                    "Host header injection can lead to: password-reset link poisoning, "
                    "web cache poisoning, SSRF, and open redirect."
                ),
                remediation=(
                    "Validate the Host header against a strict allowlist of authorised hostnames. "
                    "Never reflect the Host header value directly into Location, link, or other headers. "
                    "Set absolute_redirect off; or server_name_in_redirect off; in Nginx."
                ),
                evidence=f"Host: {injected_host} reflected in response body/headers",
                tool="cdn_bypass_scanner",
                cvss_score=_CVSS["high"],
            ))
        return vulns

    # ── Test 4: Cache-Control on authenticated responses ─────

    async def _test_cache_deception(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        result = await self._fetch(url)
        hdrs = result["headers"]

        set_cookie = hdrs.get("set-cookie", "")
        cache_control = hdrs.get("cache-control", "").lower()
        pragma = hdrs.get("pragma", "").lower()

        if set_cookie:
            no_store = "no-store" in cache_control
            no_cache = "no-cache" in cache_control
            private = "private" in cache_control
            pragma_no = "no-cache" in pragma

            if not (no_store or no_cache or private or pragma_no):
                vulns.append(Vulnerability(
                    vuln_type="cache_sensitive_response",
                    severity="medium",
                    url=url,
                    parameter="Cache-Control",
                    description=(
                        "Response sets a session cookie but does not include "
                        "Cache-Control: no-store, no-cache, or private. "
                        "The CDN may cache this response, allowing subsequent users to receive "
                        "another user's session-bound content (Web Cache Deception risk)."
                    ),
                    remediation=(
                        "Add 'Cache-Control: no-store, private' to all responses that set or "
                        "depend on session cookies. "
                        "In Nginx: add_header Cache-Control \"no-store, private\" always;"
                    ),
                    evidence=(
                        f"Set-Cookie present | Cache-Control: {hdrs.get('cache-control', '(none)')} | "
                        f"Pragma: {hdrs.get('pragma', '(none)')}"
                    ),
                    tool="cdn_bypass_scanner",
                    cvss_score=_CVSS["medium"],
                ))
        return vulns

    # ── Test 5: CDN health indicator headers ─────────────────

    async def _test_cdn_health_headers(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        result = await self._fetch(url)
        hdrs = result["headers"]

        if "x-cache-status" not in hdrs:
            vulns.append(Vulnerability(
                vuln_type="cdn_missing_cache_status",
                severity="info",
                url=url,
                parameter="X-Cache-Status",
                description=(
                    "X-Cache-Status header is absent from CDN responses. "
                    "This header is expected on CDNRay nodes (add_header X-Cache-Status ...) "
                    "and its absence indicates the CDN layer may not be serving this request, "
                    "or the header was removed."
                ),
                remediation=(
                    "Verify the CDN node is in the request path. "
                    "Confirm 'add_header X-Cache-Status $upstream_cache_status always;' "
                    "is present in the nginx location block."
                ),
                evidence="X-Cache-Status header not found in response",
                tool="cdn_bypass_scanner",
                cvss_score=_CVSS["info"],
            ))
        return vulns

    # ── helpers ──────────────────────────────────────────────

    async def _fetch(
        self,
        url: str,
        extra_headers: list[str] | None = None,
    ) -> dict:
        cmd = [
            "curl", "-s", "-I", "-L",
            "--max-time", str(self.config.timeout),
            "--max-redirs", "3",
            "-A", "Mozilla/5.0",
        ]
        for h in (extra_headers or []):
            cmd += ["-H", h]
        cmd.append(url)

        result = await run_tool(cmd, timeout=self.config.timeout + 5)
        raw = result["stdout"]
        hdrs: dict[str, str] = {}
        status: int | None = None

        for line in raw.splitlines():
            line = line.strip()
            if line.upper().startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        status = int(parts[1])
                    except ValueError:
                        pass
            elif ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()

        return {"status": status, "headers": hdrs, "raw": raw}
