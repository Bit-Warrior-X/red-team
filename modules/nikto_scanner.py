# ============================================================
# modules/nikto_scanner.py — Nikto web server probe
# ============================================================

import logging
import re
import shutil

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

OSVDB_LINE = re.compile(r"\+ (OSVDB|CVE|\d+):", re.I)


class NiktoScanner:
    """Runs nikto against a limited set of base URLs; parses notable lines."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.out_root = config.output_dir / "nikto"

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        if not shutil.which(self.config.nikto_path):
            log.warning("nikto not in PATH — install https://github.com/sullo/nikto")
            return []

        self.out_root.mkdir(parents=True, exist_ok=True)
        vulns: list[Vulnerability] = []
        limit = max(1, self.config.max_nikto_hosts)

        for url in targets[:limit]:
            if not url.startswith("http"):
                url = f"http://{url}"
            safe = re.sub(r"[^\w.-]+", "_", url)[:80]
            log_file = self.out_root / f"{safe}.txt"

            result = await run_tool(
                [self.config.nikto_path, "-h", url, "-maxtime", "120s", "-useragent", "Mozilla/5.0"],
                timeout=180,
            )
            log_file.write_text(result["stdout"], encoding="utf-8")

            for line in result["stdout"].splitlines():
                if OSVDB_LINE.search(line) or "+ INFO:" in line or "+ MAYBE:" in line:
                    vulns.append(
                        Vulnerability(
                            vuln_type="nikto_finding",
                            severity="low",
                            url=url,
                            evidence=line.strip()[:500],
                            description="Nikto signature or info line",
                            remediation="Review server config, headers, and disclosed paths; confirm impact manually",
                            tool="nikto",
                        )
                    )
        log.info("nikto pass complete (%s hosts), parsed %s lines", min(len(targets), limit), len(vulns))
        return vulns
