# ============================================================
# modules/xss_scanner.py - Dalfox Integration (enhanced)
# ============================================================
#
# Improvements over original:
# - Supports dalfox "pipe" mode: feeds parameterized crawled URLs
#   to dalfox via stdin for broader XSS surface coverage.
# - Falls back to single "url" mode per target when no crawled
#   URLs with query parameters are available.
# - Configurable via max_deep_scan_urls to cap URL count.
# ============================================================

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core.config import ScanConfig
from core.models import Asset, Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")


class XSSScanner:
    """Runs dalfox for XSS vulnerability detection."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str], crawled_urls: list[str] | None = None) -> list[Vulnerability]:
        vulns = []

        # Collect parameterized URLs from crawl for broader surface
        param_urls = self._extract_parameterized_urls(crawled_urls or [])

        if param_urls:
            log.info("XSS scanner: feeding %s parameterized URLs to dalfox pipe mode", len(param_urls))
            pipe_vulns = await self._run_pipe_mode(param_urls)
            vulns.extend(pipe_vulns)

        # Also run single-URL mode on each base target (may find form-based XSS)
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
                vulns.append(self._parse_finding(item, target))

        return vulns

    async def _run_pipe_mode(self, urls: list[str]) -> list[Vulnerability]:
        """Feed parameterized URLs to dalfox via pipe mode for bulk XSS testing."""
        if not shutil.which(self.config.dalfox_path):
            log.warning("dalfox not on PATH — skipping pipe mode")
            return []

        # Write URLs to a temp file for dalfox file mode
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_file = f.name

        result = await run_tool(
            [self.config.dalfox_path, "file", url_file,
             "--format", "json", "--silence",
             "--timeout", str(self.config.timeout),
             "--worker", str(self.config.threads)],
            timeout=600,  # longer timeout for batch
            parse_json_lines=True,
        )

        vulns = []
        for item in result["json_lines"]:
            vulns.append(self._parse_finding(item, item.get("data", "")))
        return vulns

    def _extract_parameterized_urls(self, crawled_urls: list[str]) -> list[str]:
        """Filter crawled URLs to those with query parameters (XSS test candidates)."""
        cap = max(1, self.config.max_deep_scan_urls)
        param_urls: list[str] = []
        seen: set[str] = set()

        for url in crawled_urls:
            if len(param_urls) >= cap:
                break
            try:
                parsed = urlparse(url)
                if parsed.query and url not in seen:
                    seen.add(url)
                    param_urls.append(url)
            except Exception:
                continue

        return param_urls

    def _parse_finding(self, item: dict, fallback_url: str) -> Vulnerability:
        return Vulnerability(
            vuln_type="xss",
            severity=self._map_severity(item.get("severity", "")),
            url=item.get("data", fallback_url),
            parameter=item.get("param", ""),
            payload=item.get("payload", ""),
            evidence=item.get("evidence", ""),
            description=f"XSS vulnerability found by dalfox: {item.get('type', 'reflected')}",
            remediation="Encode output, use CSP headers, validate input",
            tool="dalfox",
            raw_output=json.dumps(item),
        )

    def _map_severity(self, sev: str) -> str:
        mapping = {"high": "high", "medium": "medium", "low": "low", "verified": "high"}
        return mapping.get(sev.lower(), "medium")