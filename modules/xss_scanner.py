
# ============================================================
# modules/xss_scanner.py - Dalfox Integration
# ============================================================


import asyncio
import json
import logging
import tempfile
from pathlib import Path

from core.config import ScanConfig
from core.models import Asset, Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")


class XSSScanner:
    """Runs dalfox for XSS vulnerability detection."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns = []
        for target in targets:
            result = await run_tool(
                [self.config.dalfox_path, "url", target,
                 "--format", "json", "--silence",
                 "--timeout", str(self.config.timeout),
                 "--worker", str(self.config.threads)],
                timeout=300,
                parse_json_lines=True,
            )

            for item in result["json_lines"]:
                vulns.append(Vulnerability(
                    vuln_type="xss",
                    severity=self._map_severity(item.get("severity", "")),
                    url=item.get("data", target),
                    parameter=item.get("param", ""),
                    payload=item.get("payload", ""),
                    evidence=item.get("evidence", ""),
                    description=f"XSS vulnerability found by dalfox: {item.get('type', 'reflected')}",
                    remediation="Encode output, use CSP headers, validate input",
                    tool="dalfox",
                    raw_output=json.dumps(item),
                ))
        return vulns

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "verified": "high"}
        return mapping.get(sev.lower(), "medium")
