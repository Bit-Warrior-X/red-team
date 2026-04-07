# ============================================================
# core/crawl_fallback.py - URL discovery when xcrawl3r is missing
# ============================================================

import logging
import re
import shutil
from urllib.parse import urljoin

from core.tool_runner import run_tool

log = logging.getLogger("redscanner")

LINK_RE = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.I)


async def _curl_page_links(url: str) -> list[str]:
    """Fetch one page and return absolute http(s) URLs from href/src."""
    r = await run_tool(
        ["curl", "-s", "-L", "--max-time", "15", "-A", "Mozilla/5.0", url],
        timeout=20,
    )
    html = r["stdout"]
    if not html:
        return []
    out = []
    for m in LINK_RE.finditer(html):
        link = m.group(1).strip()
        if link.startswith(("javascript:", "mailto:", "data:", "#")):
            continue
        abs_url = urljoin(url, link)
        if abs_url.startswith("http"):
            out.append(abs_url)
    return list(dict.fromkeys(out))


async def xcrawl3r_or_fallback_pages(
    seed_urls: list[str], xcrawl3r_path: str, depth: int | None = None
) -> list[str]:
    """
    Discover HTTP(S) URLs (for recon). Uses xcrawl3r when installed;
    otherwise curls each seed once and extracts links from HTML.

    xcrawl3r: `-d` / `--domain` is scope, not depth. Crawl depth is `--depth` (default 1).
    Default: `xcrawl3r -u <url>` only; pass `depth=N` to add `--depth N`.
    """
    if shutil.which(xcrawl3r_path):
        all_urls: list[str] = []
        for url in seed_urls[:5]:
            cmd = [xcrawl3r_path, "-u", url]
            if depth is not None:
                cmd.extend(["--depth", str(depth)])
            result = await run_tool(
                cmd,
                timeout=120,
            )
            for line in result["stdout"].strip().split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    all_urls.append(line)
        return list(dict.fromkeys(all_urls))

    log.info(
        "xcrawl3r not in PATH; using curl + HTML link extraction (single-hop, limited coverage)"
    )
    all_urls: list[str] = []
    for url in seed_urls[:5]:
        all_urls.extend(await _curl_page_links(url))
    return list(dict.fromkeys(all_urls))


async def xcrawl3r_or_fallback_js(
    target: str, xcrawl3r_path: str, depth: int | None = None
) -> list[str]:
    """
    Discover .js URLs (for API leak scanning). Uses xcrawl3r when installed;
    otherwise extracts script/src links from the landing HTML only.
    """
    if shutil.which(xcrawl3r_path):
        cmd = [xcrawl3r_path, "-u", target]
        if depth is not None:
            cmd.extend(["--depth", str(depth)])
        result = await run_tool(
            cmd,
            timeout=120,
        )
        return [
            line.strip()
            for line in result["stdout"].split("\n")
            if line.strip().endswith(".js") or ".js?" in line
        ]

    log.info(
        "xcrawl3r not in PATH; scanning .js URLs from landing page HTML only"
    )
    links = await _curl_page_links(target)
    return [
        u
        for u in links
        if u.endswith(".js") or ".js?" in u
    ]
