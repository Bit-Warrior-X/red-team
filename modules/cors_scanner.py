# ============================================================
# modules/cors_scanner.py — CORS misconfiguration detection
# Maps to: OWASP WSTG-CLIENT-07 (Testing Cross Origin Resource Sharing)
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

# Origins used to probe for reflection
_TEST_ORIGINS = [
    "https://evil.example.com",
    "null",
]


class CORSScanner:
    """
    Tests for CORS misconfigurations using curl HEAD/GET requests.

    Checks performed:
    1. Wildcard Access-Control-Allow-Origin: * — moderate risk
    2. Arbitrary origin reflected (ACAO mirrors Origin header) — high
    3. Credentialed CORS: reflected origin + Allow-Credentials: true — critical
    4. Domain-suffix spoof: attacker.target.com reflected — high
    5. Null origin reflected — medium
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for url in targets:
            vulns.extend(await self._test_url(url))
        log.info("CORS scanner reported %s findings", len(vulns))
        return vulns

    async def _test_url(self, url: str) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        hostname = parsed.hostname or ""

        # Test 1: No Origin header — check for unconditional wildcard
        baseline_hdrs = await self._fetch_headers(url)
        if baseline_hdrs is not None:
            acao = baseline_hdrs.get("access-control-allow-origin", "")
            if acao == "*":
                vulns.append(Vulnerability(
                    vuln_type="cors_wildcard",
                    severity="medium",
                    url=url,
                    parameter="Access-Control-Allow-Origin",
                    description=(
                        "Response includes Access-Control-Allow-Origin: * without any Origin in the request. "
                        "Any website can read responses from this endpoint. The risk is lower for endpoints "
                        "that don't serve sensitive data, but should be reviewed."
                    ),
                    remediation=(
                        "Replace the wildcard with an explicit allowlist of trusted origins. "
                        "Never use * on endpoints that serve authenticated or sensitive data."
                    ),
                    evidence="Access-Control-Allow-Origin: *",
                    tool="cors_scanner",
                    cvss_score=_CVSS["medium"],
                ))

        # Test 2: Reflect a fully arbitrary external origin
        for test_origin in _TEST_ORIGINS:
            v = await self._probe_reflection(url, test_origin)
            if v:
                vulns.append(v)

        # Test 3: Domain-suffix spoof — attacker domain ending with the real hostname
        if hostname:
            spoofed = f"https://attacker-{hostname}"
            v = await self._probe_reflection(url, spoofed)
            if v:
                vulns.append(v)

            # Sub-domain prefix spoof (evil.subdomain.target.com)
            spoofed2 = f"https://evil.{hostname}"
            v2 = await self._probe_reflection(url, spoofed2)
            if v2:
                vulns.append(v2)

        return vulns

    async def _probe_reflection(self, url: str, test_origin: str) -> Vulnerability | None:
        """Send Origin: <test_origin> and check if ACAO reflects it."""
        hdrs = await self._fetch_headers(url, extra_headers=[f"Origin: {test_origin}"])
        if hdrs is None:
            return None

        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").strip().lower() == "true"

        if acao != test_origin:
            return None

        # Origin is reflected
        if acac:
            return Vulnerability(
                vuln_type="cors_credentialed",
                severity="critical",
                url=url,
                parameter="Access-Control-Allow-Origin",
                description=(
                    f"Credentialed CORS misconfiguration: the server reflects Origin '{test_origin}' "
                    "back in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. "
                    "An attacker can make fully authenticated cross-origin requests from any page they control, "
                    "reading session-bound responses and exfiltrating user data."
                ),
                remediation=(
                    "Validate the Origin header against a strict server-side allowlist before reflecting it. "
                    "Never set Allow-Credentials: true alongside a dynamically reflected or wildcard ACAO. "
                    "Use an explicit list: if (ALLOWED_ORIGINS.contains(origin)) response.setHeader(ACAO, origin)."
                ),
                evidence=(
                    f"Origin: {test_origin} → "
                    f"Access-Control-Allow-Origin: {acao} | "
                    f"Access-Control-Allow-Credentials: true"
                ),
                tool="cors_scanner",
                cvss_score=_CVSS["critical"],
            )
        else:
            return Vulnerability(
                vuln_type="cors_reflected_origin",
                severity="high",
                url=url,
                parameter="Access-Control-Allow-Origin",
                description=(
                    f"CORS reflected origin: the server echoes back arbitrary Origin '{test_origin}' "
                    "in Access-Control-Allow-Origin. Any attacker-controlled website can issue cross-origin "
                    "GET/POST requests to this endpoint and read the response (without credentials)."
                ),
                remediation=(
                    "Do not reflect the request Origin header directly. "
                    "Validate against a strict origin allowlist on the server side."
                ),
                evidence=f"Origin: {test_origin} → Access-Control-Allow-Origin: {acao}",
                tool="cors_scanner",
                cvss_score=_CVSS["high"],
            )

    async def _fetch_headers(
        self,
        url: str,
        extra_headers: list[str] | None = None,
    ) -> dict[str, str] | None:
        """Fetch response headers via curl -I."""
        cmd = [
            "curl", "-s", "-I", "-L",
            "--max-time", str(self.config.timeout),
            "-A", "Mozilla/5.0",
        ]
        for h in (extra_headers or []):
            cmd += ["-H", h]
        cmd.append(url)

        result = await run_tool(cmd, timeout=self.config.timeout + 5)
        if not result["stdout"]:
            return None

        headers: dict[str, str] = {}
        for line in result["stdout"].splitlines():
            line = line.strip()
            if ":" in line and not line.upper().startswith("HTTP/"):
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return headers if headers else None
