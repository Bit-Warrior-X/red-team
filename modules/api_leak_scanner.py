
# ============================================================
# modules/api_leak_scanner.py - JS API Key Leak Detection
# ============================================================

from core.config import ScanConfig
from core.crawl_fallback import xcrawl3r_or_fallback_js
from core.models import Vulnerability
from core.tool_runner import run_tool


class APILeakScanner:
    """Scans JS files for leaked API keys using pattern matching."""

    # Based on mantra tool patterns
    PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36}",
        "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "JWT": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "Generic Secret": r"(?i)(secret|password|token|apikey|api_key)['\"]?\s*[:=]\s*['\"][^\s'\"]{8,}['\"]",
    }

    def __init__(self, config: ScanConfig):
        self.config = config

    async def run(self, targets: list[str]) -> list[Vulnerability]:
        import re
        vulns = []

        for target in targets:
            js_urls = await xcrawl3r_or_fallback_js(target, self.config.xcrawl3r_path)

            # Check each JS file for leaks
            for js_url in js_urls[:20]:  # cap to avoid overload
                fetch_result = await run_tool(
                    ["curl", "-s", "-L", "--max-time", "10", js_url],
                    timeout=15,
                )
                content = fetch_result["stdout"]
                if not content:
                    continue

                for name, pattern in self.PATTERNS.items():
                    matches = re.findall(pattern, content)
                    for match in matches:
                        match_str = match if isinstance(match, str) else match[0]
                        # Redact most of the match for safety
                        redacted = match_str[:8] + "..." + match_str[-4:] if len(match_str) > 12 else match_str
                        vulns.append(Vulnerability(
                            vuln_type="api_key_leak",
                            severity="high",
                            url=js_url,
                            evidence=f"{name}: {redacted}",
                            description=f"Potential {name} leak found in JavaScript file",
                            remediation="Remove hardcoded secrets, use environment variables, rotate exposed keys",
                            tool="api_leak_scanner",
                        ))
        return vulns