# ============================================================
# modules/wayback_enricher.py — waybackurls + gau
# ============================================================

import logging
import shutil

from core.config import ScanConfig
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")


class WaybackEnricher:
    """
    Historical URL discovery to widen nuclei/dalfox surface.
    Historical URL discovery via waybackurls and gau.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = config.output_dir / "recon"

    async def run(self, domains: set[str]) -> list[str]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        urls: list[str] = []
        cap = max(1, self.config.max_wayback_urls)
        # Bound domains to avoid huge runs on large scopes
        for domain in sorted(domains)[:80]:
            if len(urls) >= cap:
                break
            if shutil.which(self.config.waybackurls_path):
                r = await run_tool(
                    [self.config.waybackurls_path],
                    timeout=120,
                    stdin_input=f"{domain}\n",
                )
                for line in r["stdout"].splitlines():
                    line = line.strip()
                    if line.startswith("http") and len(urls) < cap:
                        urls.append(line)
            if shutil.which(self.config.gau_path):
                r2 = await run_tool(
                    [self.config.gau_path, domain],
                    timeout=120,
                )
                for line in r2["stdout"].splitlines():
                    line = line.strip()
                    if line.startswith("http") and len(urls) < cap:
                        urls.append(line)

        # Dedupe preserving order
        seen = set()
        unique: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)

        out_file = self.output_dir / "wayback_gau_urls.txt"
        out_file.write_text("\n".join(unique), encoding="utf-8")
        log.info("Wayback/gau collected %s URLs (cap %s)", len(unique), cap)
        return unique[:cap]
