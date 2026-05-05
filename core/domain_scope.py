# ============================================================
# core/domain_scope.py — restrict findings to a scoped hostname
# ============================================================

from __future__ import annotations

import re
from urllib.parse import urlparse

from core.models import Vulnerability

TCP_RE = re.compile(r"^tcp://([^/:]+):(\d+)\s*$", re.I)


def _host_from_finding_url(url: str) -> str | None:
    if not url:
        return None
    u = url.strip()
    if u.startswith(("http://", "https://")):
        try:
            return (urlparse(u).hostname or "").lower() or None
        except Exception:
            return None
    m = TCP_RE.match(u)
    if m:
        return m.group(1).lower()
    return None


def host_under_target(hostname: str | None, target: str) -> bool:
    """True if hostname is target or a subdomain of target (e.g. api.example.com under example.com)."""
    if not hostname:
        return True
    if not target:
        return True
    h = hostname.lower().rstrip(".")
    t = target.lower().rstrip(".")
    if not h or not t:
        return True
    return h == t or h.endswith("." + t)


def finding_matches_target(vuln: Vulnerability, target: str) -> bool:
    """Whether a finding should appear in strict domain-scoped reports."""
    host = _host_from_finding_url(vuln.url)
    return host_under_target(host, target)
