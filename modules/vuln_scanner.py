# ============================================================
# modules/vuln_scanner.py - Nuclei Integration (enhanced)
# ============================================================
#
# Improvements:
# - First-class nuclei_tags / nuclei_exclude_tags support from
#   red_plan.json (e.g. -tags cve,oast; -etags dos,fuzz)
# - nuclei_extra_args still supported for arbitrary flags
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

        cmd = [
            self.config.nuclei_path,
            "-l",
            input_file,
            "-json",
            "-silent",
            "-severity",
            "critical,high,medium,low",
            "-rate-limit",
            str(self.config.rate_limit),
            "-c",
            str(self.config.threads),
        ]

        # First-class template tag control
        if self.config.nuclei_tags:
            tag_str = ",".join(t.strip() for t in self.config.nuclei_tags if t.strip())
            if tag_str:
                cmd.extend(["-tags", tag_str])
                log.info("Nuclei template include tags: %s", tag_str)
        if self.config.nuclei_exclude_tags:
            etag_str = ",".join(t.strip() for t in self.config.nuclei_exclude_tags if t.strip())
            if etag_str:
                cmd.extend(["-etags", etag_str])
                log.info("Nuclei template exclude tags: %s", etag_str)

        # Extra arbitrary args (backward compatible)
        for arg in self.config.nuclei_extra_args:
            if isinstance(arg, str) and arg.strip():
                cmd.append(arg.strip())

        result = await run_tool(
            cmd,
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