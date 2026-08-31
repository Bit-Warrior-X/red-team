
# ============================================================
# core/db.py - SQLite results storage
# ============================================================


from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import os
import sqlite3

from core.models import Asset, Vulnerability


class ResultsDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(self.db_path.parent, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                url TEXT,
                ip TEXT,
                port INTEGER,
                status_code INTEGER,
                title TEXT,
                alive BOOLEAN,
                source TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                module TEXT,
                vuln_type TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                description TEXT,
                remediation TEXT,
                cvss_score REAL,
                cve_id TEXT,
                tool TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.close()

    def save_assets(self, scan_id: str, assets: list[Asset]):
        conn = sqlite3.connect(self.db_path)
        for a in assets:
            conn.execute(
                "INSERT INTO assets (scan_id, url, ip, port, status_code, title, alive, source) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, a.url, a.ip, a.port, a.status_code, a.title, a.alive, a.source),
            )
        conn.commit()
        conn.close()

    def save_vulns(self, scan_id: str, vulns: list[Vulnerability], module: str = ""):
        """Persist findings for one module run. Called incrementally after each
        module completes (not just once at the end) so that --resume has an
        accurate on-disk record even if the process is interrupted mid-scan."""
        conn = sqlite3.connect(self.db_path)
        for v in vulns:
            conn.execute(
                "INSERT INTO vulnerabilities "
                "(scan_id, module, vuln_type, severity, url, parameter, payload, evidence, "
                "description, remediation, cvss_score, cve_id, tool) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, module, v.vuln_type, v.severity, v.url, v.parameter, v.payload,
                 v.evidence, v.description, v.remediation, v.cvss_score, v.cve_id, v.tool),
            )
        conn.commit()
        conn.close()

    def load_assets(self, scan_id: str) -> list[Asset]:
        """Reconstruct previously-saved assets for a scan_id (used by --resume
        to restore recon state without re-running subfinder/httpx)."""
        if not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT url, ip, port, status_code, title, alive, source "
                "FROM assets WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        finally:
            conn.close()
        return [
            Asset(
                url=row[0],
                ip=row[1],
                port=row[2],
                status_code=row[3],
                title=row[4],
                tech=[],  # not persisted; acceptable loss on resume
                alive=bool(row[5]),
                source=row[6] or "",
            )
            for row in rows
        ]

    def load_vulns(self, scan_id: str, module: Optional[str] = None) -> list[Vulnerability]:
        """Reconstruct previously-saved findings for a scan_id (optionally
        filtered to one module) — used by --resume to restore results for
        modules that already completed in an earlier, interrupted run."""
        if not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        try:
            if module:
                rows = conn.execute(
                    "SELECT vuln_type, severity, url, parameter, payload, evidence, "
                    "description, remediation, cvss_score, cve_id, tool "
                    "FROM vulnerabilities WHERE scan_id = ? AND module = ?",
                    (scan_id, module),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT vuln_type, severity, url, parameter, payload, evidence, "
                    "description, remediation, cvss_score, cve_id, tool "
                    "FROM vulnerabilities WHERE scan_id = ?",
                    (scan_id,),
                ).fetchall()
        finally:
            conn.close()
        return [
            Vulnerability(
                vuln_type=row[0],
                severity=row[1],
                url=row[2],
                parameter=row[3],
                payload=row[4],
                evidence=row[5],
                description=row[6] or "",
                remediation=row[7] or "",
                cvss_score=row[8],
                cve_id=row[9],
                tool=row[10] or "",
            )
            for row in rows
        ]
