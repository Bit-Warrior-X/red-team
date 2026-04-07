
# ============================================================
# modules/sqli_scanner.py - sqlmap API Mode
# ============================================================


import logging

from core.config import ScanConfig
from core.models import Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

class SQLiScanner:
    """Runs sqlmap in API/batch mode for SQL injection testing."""

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        vulns = []
        for target in targets:
            result = await run_tool(
                [self.config.sqlmap_path, "-u", target,
                 "--batch", "--smart", "--level", "2", "--risk", "1",
                 "--output-dir", str(self.config.output_dir / "sqlmap"),
                 "--forms", "--crawl=2"],
                timeout=300,
            )

            stdout = result["stdout"]
            if "is vulnerable" in stdout.lower() or "injectable" in stdout.lower():
                # Parse sqlmap output for injection points
                for line in stdout.split("\n"):
                    if "parameter" in line.lower() and "injectable" in line.lower():
                        vulns.append(Vulnerability(
                            vuln_type="sqli",
                            severity="critical",
                            url=target,
                            parameter=self._extract_param(line),
                            description=f"SQL injection found: {line.strip()}",
                            remediation="Use parameterized queries / prepared statements",
                            tool="sqlmap",
                            raw_output=stdout[:2000],
                        ))
        return vulns

    def _extract_param(self, line: str) -> str:
        # Try to extract parameter name from sqlmap output
        for marker in ["parameter '", 'parameter "']:
            if marker in line.lower():
                start = line.lower().index(marker) + len(marker)
                end = line.index("'", start) if "'" in line[start:] else len(line)
                return line[start:end]
        return "unknown"
