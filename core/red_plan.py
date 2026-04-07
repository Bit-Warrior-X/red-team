# ============================================================
# core/red_plan.py — load engagement plan from assets/red_plan.json
# ============================================================

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("redscanner")


def load_red_plan(path: Path) -> dict[str, Any]:
    """Load JSON plan: profiles, manual phases, methodology, etc."""
    if not path.is_file():
        log.debug("No red plan file: %s", path)
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as e:
        log.warning("Could not read red plan %s: %s", path, e)
        return {}


def merge_profiles(default: dict[str, list[str]], plan: dict[str, Any]) -> dict[str, list[str]]:
    """Overlay profiles from red_plan.json onto built-in defaults."""
    merged = dict(default)
    raw = plan.get("profiles")
    if isinstance(raw, dict):
        for name, mods in raw.items():
            if isinstance(mods, list):
                merged[name] = [str(m).strip() for m in mods if str(m).strip()]
    return merged
