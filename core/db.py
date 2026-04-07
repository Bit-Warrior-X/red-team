
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

    def save_vulns(self, scan_id: str, vulns: list[Vulnerability]):
        conn = sqlite3.connect(self.db_path)
        for v in vulns:
            conn.execute(
                "INSERT INTO vulnerabilities (scan_id, vuln_type, severity, url, parameter, payload, evidence, description, remediation, cvss_score, cve_id, tool) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, v.vuln_type, v.severity, v.url, v.parameter, v.payload, v.evidence, v.description, v.remediation, v.cvss_score, v.cve_id, v.tool),
            )
        conn.commit()
        conn.close()
