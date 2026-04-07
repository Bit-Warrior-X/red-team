
import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core.config import ScanConfig
from core.crawl_fallback import xcrawl3r_or_fallback_pages
from core.models import Asset, Vulnerability
from core.tool_runner import run_tool

log = logging.getLogger("redscanner")


# ============================================================
# modules/recon.py - Subdomain & Asset Discovery
# ============================================================

class ReconEngine:
    """Chains: subfinder → assetfinder (optional) → httpx → xcrawl3r for full recon."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.output_dir = config.output_dir / "recon"
        self.discovered_domains: set[str] = set()
        self.crawled_urls: list[str] = []

    async def run(self) -> list[Asset]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        assets = []

        # Step 1: Subdomain enumeration with subfinder
        subs = await self._subfinder()
        subs.add(self.config.target)  # always include main target
        subs |= await self._assetfinder()

        self.discovered_domains = set(subs)

        # Step 2: HTTP probing with httpx
        assets = await self._httpx(subs)

        # Step 3: URL crawling with xcrawl3r on alive hosts
        alive_urls = [a.url for a in assets if a.alive]
        if alive_urls:
            crawled = await self._xcrawl3r(alive_urls)
            self.crawled_urls = sorted(set(crawled))
            log.info(f"Crawled {len(crawled)} URLs from alive hosts")
        else:
            self.crawled_urls = []

        return assets

    async def _subfinder(self) -> set[str]:
        result = await run_tool(
            [self.config.subfinder_path, "-d", self.config.target, "-silent", "-all"],
            timeout=120,
        )
        subs = set()
        for line in result["stdout"].strip().split("\n"):
            line = line.strip()
            if line:
                subs.add(line)
        log.info(f"subfinder found {len(subs)} subdomains")

        # Save to file for other tools
        subs_file = self.output_dir / "subdomains.txt"
        subs_file.write_text("\n".join(sorted(subs)))
        return subs

    async def _assetfinder(self) -> set[str]:
        """Optional CT/API subdomain pass (complements subfinder)."""
        if not shutil.which(self.config.assetfinder_path):
            log.info(
                "assetfinder not on PATH — install https://github.com/tomnomnom/assetfinder "
                "to merge passive subdomain hints (optional)."
            )
            return set()
        result = await run_tool(
            [self.config.assetfinder_path, self.config.target],
            timeout=90,
        )
        found = set()
        for line in result["stdout"].strip().split("\n"):
            line = line.strip()
            if line:
                found.add(line)
        if found:
            log.info("assetfinder added %s hostnames", len(found))
        return found

    async def _httpx(self, domains: set[str]) -> list[Asset]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            input_file = f.name

        result = await run_tool(
            [self.config.httpx_path, "-l", input_file, "-json",
             "-status-code", "-title", "-tech-detect", "-silent"],
            timeout=180,
            parse_json_lines=True,
        )

        assets = []
        for item in result["json_lines"]:
            url = item.get("url", "")
            port = item.get("port")
            if port is None and url:
                try:
                    p = urlparse(url)
                    if p.port is not None:
                        port = p.port
                except Exception:
                    pass
            ip = item.get("ip") or item.get("host") or ""
            if isinstance(ip, list):
                ip = ip[0] if ip else ""
            assets.append(Asset(
                url=url,
                ip=str(ip) if ip else None,
                port=int(port) if port is not None else None,
                status_code=item.get("status_code"),
                title=item.get("title", ""),
                tech=item.get("tech", []) if isinstance(item.get("tech"), list) else [],
                alive=item.get("status_code", 0) < 500,
                source="httpx",
            ))
        return assets

    async def _xcrawl3r(self, urls: list[str]) -> list[str]:
        all_urls = await xcrawl3r_or_fallback_pages(
            urls, self.config.xcrawl3r_path, depth=None
        )
        crawled_file = self.output_dir / "crawled_urls.txt"
        crawled_file.write_text("\n".join(sorted(set(all_urls))))
        return all_urls
