
# ============================================================
# modules/vuln_scanner.py - Nuclei Integration
# ============================================================


import json
import logging
import tempfile
from urllib.parse import parse_qs, urlparse

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

class VulnScanner:
    """Runs nuclei templates against discovered targets."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            input_file = f.name

        result = await run_tool(
            [self.config.nuclei_path, "-l", input_file, "-json", "-silent",
             "-severity", "critical,high,medium,low",
             "-rate-limit", str(self.config.rate_limit),
             "-c", str(self.config.threads)],
            timeout=600,
            parse_json_lines=True,
        )

        vulns = []
        for item in result["json_lines"]:
            info = item.get("info", {})
            matched = item.get("matched-at") or item.get("host", "")
            param = None
            if matched:
                keys = list(parse_qs(urlparse(matched).query, keep_blank_values=True).keys())
                if keys:
                    param = keys[0]
            vulns.append(Vulnerability(
                vuln_type=info.get("name", "unknown"),
                severity=info.get("severity", "info"),
                url=matched,
                parameter=param or None,
                description=info.get("description", ""),
                remediation=info.get("remediation", ""),
                cvss_score=info.get("classification", {}).get("cvss-score"),
                cve_id=info.get("classification", {}).get("cve-id"),
                evidence=item.get("matcher-name", "") or item.get("template-id", ""),
                tool="nuclei",
                raw_output=json.dumps(item),
            ))
        return vulns
