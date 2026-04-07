# ============================================================
# modules/naabu_scanner.py — fast port discovery (ProjectDiscovery)
# ============================================================

import logging
import re
import shutil

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

HOST_PORT_RE = re.compile(r"^([^\s:]+):(\d+)\s*$")


class NaabuScanner:
    """Runs naabu against discovered hostnames; records open ports as informational findings."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = config.output_dir / "recon"

    async def run(self, domains: set[str]) -> list[Vulnerability]:
        if not shutil.which(self.config.naabu_path):
            log.warning("naabu not in PATH — install https://github.com/projectdiscovery/naabu")
            return []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        vulns: list[Vulnerability] = []
        host_file = self.output_dir / "naabu_hosts.txt"
        host_file.write_text("\n".join(sorted(domains)[:200]), encoding="utf-8")

        result = await run_tool(
            [
                self.config.naabu_path,
                "-l",
                str(host_file),
                "-silent",
                "-top-ports",
                "1000",
                "-rate",
                "500",
            ],
            timeout=600,
        )
        raw_path = self.output_dir / "naabu_raw.txt"
        raw_path.write_text(result["stdout"], encoding="utf-8")

        for line in result["stdout"].splitlines():
            line = line.strip()
            m = HOST_PORT_RE.match(line)
            if m:
                host, port = m.group(1), m.group(2)
                vulns.append(
                    Vulnerability(
                        vuln_type="open_port",
                        severity="info",
                        url=f"tcp://{host}:{port}",
                        description=f"Responsive port {port}/tcp on {host} (naabu)",
                        remediation="Validate exposure against architecture; restrict firewall/WAF as designed",
                        tool="naabu",
                    )
                )
        log.info("naabu reported %s open ports (info findings)", len(vulns))
        return vulns
