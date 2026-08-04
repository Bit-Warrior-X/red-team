# ============================================================
# modules/tls_scanner.py — TLS/SSL version and certificate assessment
# Maps to: OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security)
# Tools: testssl.sh (preferred), openssl s_client fallback
# ============================================================

from __future__ import annotations

import json as _json
import logging
import os
import re
import shutil
import tempfile
from urllib.parse import urlparse

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

_CVSS: dict[str, float] = {
    "critical": 9.1,
    "high": 7.5,
    "medium": 5.9,
    "low": 3.1,
    "info": 0.0,
}

# testssl.sh severity → RedScanner severity
_TESTSSL_SEV = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": None,      # good — skip
    "NOT OK": "medium",
    "WARN": "low",
    "DEBUG": "info",
}


class TLSScanner:
    """
    Assesses TLS/SSL configuration of HTTPS endpoints.

    Uses testssl.sh if it is on PATH (comprehensive JSON output);
    otherwise falls back to openssl s_client probes:
      - TLS 1.0 / 1.1 still accepted (POODLE / BEAST risk)
      - Certificate validity (expired, self-signed)
      - TLS 1.3 availability
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        # Collect unique host:port pairs from https:// targets and port-443 fallback
        seen: set[str] = set()
        host_ports: list[str] = []

        for url in targets:
            hp = self._to_host_port(url, force_443=False)
            if hp and hp not in seen:
                seen.add(hp)
                host_ports.append(hp)

        for url in targets:
            hp = self._to_host_port(url, force_443=True)
            if hp and hp not in seen:
                seen.add(hp)
                host_ports.append(hp)

        if not host_ports:
            log.info("TLS scanner: no HTTPS targets, probing port 443 on base target")
            host_ports = [f"{self.config.target}:443"]

        use_testssl = bool(shutil.which(self.config.testssl_path))
        if use_testssl:
            log.info("TLS scanner: using testssl.sh")
        else:
            log.info("TLS scanner: testssl.sh not found — using openssl fallback (install testssl.sh for full assessment)")

        vulns: list[Vulnerability] = []
        for hp in host_ports:
            if use_testssl:
                v = await self._run_testssl(hp)
            else:
                v = await self._run_openssl(hp)
            vulns.extend(v)

        log.info("TLS scanner reported %s findings", len(vulns))
        return vulns

    # ── helpers ──────────────────────────────────────────────

    def _to_host_port(self, url: str, force_443: bool) -> str | None:
        try:
            p = urlparse(url if url.startswith("http") else f"https://{url}")
            host = p.hostname or ""
            if not host:
                return None
            if p.scheme == "https" or force_443:
                port = p.port or 443
                return f"{host}:{port}"
        except Exception:
            pass
        return None

    # ── testssl.sh ────────────────────────────────────────────

    async def _run_testssl(self, host_port: str) -> list[Vulnerability]:
        host, port = host_port.rsplit(":", 1)
        fd, out_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            await run_tool(
                [
                    self.config.testssl_path,
                    "--jsonfile", out_file,
                    "--severity", "LOW",
                    "--quiet",
                    "--color", "0",
                    "--warnings", "off",
                    host_port,
                ],
                timeout=180,
            )

            if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
                log.warning("testssl.sh: no JSON output for %s — falling back to openssl", host_port)
                return await self._run_openssl(host_port)

            try:
                raw = open(out_file, encoding="utf-8", errors="replace").read()
                data = _json.loads(raw)
            except Exception as exc:
                log.warning("testssl.sh: JSON parse error for %s: %s", host_port, exc)
                return await self._run_openssl(host_port)

            return self._parse_testssl_json(data, host_port)
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    def _parse_testssl_json(self, data: object, host_port: str) -> list[Vulnerability]:
        """Parse testssl.sh JSON output (both flat-list and scanResult formats)."""
        vulns: list[Vulnerability] = []

        # testssl.sh can produce either a list of findings or {"scanResult": [...]}
        findings: list[dict] = []
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            for scan in data.get("scanResult", []):
                findings.extend(scan.get("findings", []))

        seen_ids: set[str] = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev_raw = str(f.get("severity", "INFO")).upper()
            sev = _TESTSSL_SEV.get(sev_raw)
            if sev is None:
                continue  # OK result — no issue

            finding_id = str(f.get("id", "unknown"))
            finding_text = str(f.get("finding", ""))
            key = f"{finding_id}:{finding_text[:80]}"
            if key in seen_ids:
                continue
            seen_ids.add(key)

            vulns.append(Vulnerability(
                vuln_type=f"tls_{finding_id.lower().replace('-', '_').replace(' ', '_')}",
                severity=sev,
                url=f"https://{host_port}",
                parameter=finding_id,
                description=f"testssl.sh: {finding_text}",
                remediation="Review testssl.sh output and apply TLS hardening per finding.",
                evidence=f"[{sev_raw}] {finding_id}: {finding_text[:300]}",
                tool="testssl.sh",
                cvss_score=_CVSS.get(sev, 0.0),
            ))

        return vulns

    # ── openssl fallback ──────────────────────────────────────

    async def _run_openssl(self, host_port: str) -> list[Vulnerability]:
        host, _ = host_port.rsplit(":", 1)
        vulns: list[Vulnerability] = []

        # Probe legacy TLS versions
        for flag, version, cvss in [
            ("-tls1",   "TLS 1.0", 5.9),
            ("-tls1_1", "TLS 1.1", 5.9),
        ]:
            result = await run_tool(
                [
                    "openssl", "s_client",
                    "-connect", host_port,
                    "-servername", host,
                    flag, "-brief",
                ],
                stdin_input="Q",
                timeout=12,
            )
            out = result["stdout"] + result["stderr"]
            # A successful handshake shows CONNECTED or the protocol line
            if re.search(r"CONNECTED|SSL handshake has read", out, re.IGNORECASE):
                vulns.append(Vulnerability(
                    vuln_type="tls_legacy_version",
                    severity="medium",
                    url=f"https://{host_port}",
                    parameter=version,
                    description=(
                        f"{version} is still accepted by the server. "
                        "This version has known cryptographic weaknesses (POODLE, BEAST) "
                        "and is deprecated by RFC 8996."
                    ),
                    remediation=(
                        f"Disable {version}: set ssl_protocols TLSv1.2 TLSv1.3; "
                        "in your nginx/OpenResty config."
                    ),
                    evidence=f"openssl s_client {flag} connected successfully to {host_port}",
                    tool="tls_scanner",
                    cvss_score=cvss,
                ))

        # Certificate check
        cert_result = await run_tool(
            [
                "openssl", "s_client",
                "-connect", host_port,
                "-servername", host,
                "-brief",
            ],
            stdin_input="Q",
            timeout=12,
        )
        cert_out = cert_result["stdout"] + cert_result["stderr"]

        if re.search(r"self[- ]signed certificate", cert_out, re.IGNORECASE):
            vulns.append(Vulnerability(
                vuln_type="tls_self_signed_cert",
                severity="medium",
                url=f"https://{host_port}",
                parameter="X.509 Certificate",
                description=(
                    "Server presents a self-signed certificate. "
                    "Clients cannot verify server identity, enabling MITM attacks."
                ),
                remediation=(
                    "Replace the self-signed certificate with one signed by a trusted CA. "
                    "Use Let's Encrypt (certbot) for free automated certificates."
                ),
                evidence="openssl: self-signed certificate in chain",
                tool="tls_scanner",
                cvss_score=_CVSS["medium"],
            ))

        if re.search(r"certificate has expired|verify error:num=10", cert_out, re.IGNORECASE):
            exp_match = re.search(r"notAfter=(.+)", cert_out, re.IGNORECASE)
            evidence = exp_match.group(0).strip() if exp_match else "certificate expiry detected"
            vulns.append(Vulnerability(
                vuln_type="tls_expired_cert",
                severity="medium",
                url=f"https://{host_port}",
                parameter="X.509 Certificate",
                description=(
                    "TLS certificate is expired. Browsers show security warnings and "
                    "automated clients may refuse to connect."
                ),
                remediation=(
                    "Renew the certificate immediately. "
                    "Enable auto-renewal via ACME/certbot to prevent recurrence."
                ),
                evidence=evidence,
                tool="tls_scanner",
                cvss_score=_CVSS["medium"],
            ))

        # TLS 1.3 availability (informational)
        tls13 = await run_tool(
            [
                "openssl", "s_client",
                "-connect", host_port,
                "-servername", host,
                "-tls1_3", "-brief",
            ],
            stdin_input="Q",
            timeout=12,
        )
        tls13_out = tls13["stdout"] + tls13["stderr"]
        if not re.search(r"CONNECTED|SSL handshake has read", tls13_out, re.IGNORECASE):
            vulns.append(Vulnerability(
                vuln_type="tls_no_tls13",
                severity="info",
                url=f"https://{host_port}",
                parameter="TLS 1.3",
                description=(
                    "TLS 1.3 is not offered. While not a direct vulnerability, "
                    "TLS 1.3 removes legacy cipher suites and provides stronger forward secrecy."
                ),
                remediation="Add TLSv1.3 to ssl_protocols: ssl_protocols TLSv1.2 TLSv1.3;",
                evidence=f"openssl s_client -tls1_3 did not connect to {host_port}",
                tool="tls_scanner",
                cvss_score=_CVSS["info"],
            ))

        return vulns
