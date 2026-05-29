import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "trinetra.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # main scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id         TEXT PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            url             TEXT NOT NULL,
            target_org      TEXT,
            url_score       REAL,
            behavior_score  REAL,
            visual_score    REAL,
            final_score     REAL,
            risk_level      TEXT,
            flags           TEXT,
            shap_values     TEXT,
            eye1_result     TEXT,
            eye3_result     TEXT,
            visual_pending  INTEGER DEFAULT 1
        )
    """)

    # whois cache table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whois_cache (
            domain      TEXT PRIMARY KEY,
            age_days    INTEGER,
            registrar   TEXT,
            fetched_at  TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(scan_data: dict) -> str:
    """Save a scan result. Returns scan_id."""
    scan_id = str(uuid.uuid4())
    conn = get_connection()
    conn.execute("""
        INSERT INTO scans (
            scan_id, timestamp, url, target_org,
            url_score, behavior_score, visual_score,
            final_score, risk_level, flags,
            eye1_result, eye3_result, visual_pending
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        datetime.utcnow().isoformat(),
        scan_data["url"],
        scan_data.get("target_org"),
        scan_data.get("url_score"),
        scan_data.get("behavior_score"),
        scan_data.get("visual_score"),
        scan_data.get("final_score"),
        scan_data.get("risk_level"),
        json.dumps(scan_data.get("flags", [])),
        json.dumps(scan_data.get("eye1_result", {})),
        json.dumps(scan_data.get("eye3_result", {})),
        1  # visual always starts as pending
    ))
    conn.commit()
    conn.close()
    return scan_id


def update_visual(scan_id: str, visual_score: float,
                  final_score: float, risk_level: str,
                  visual_flags: list):
    """Update scan with visual result once Eye 2 completes."""
    conn = get_connection()
    conn.execute("""
        UPDATE scans
        SET visual_score   = ?,
            final_score    = ?,
            risk_level     = ?,
            visual_pending = 0,
            flags          = (
                SELECT json(
                    json_group_array(value)
                )
                FROM (
                    SELECT value FROM json_each(flags)
                    UNION ALL
                    SELECT value FROM json_each(?)
                )
            )
        WHERE scan_id = ?
    """, (visual_score, final_score, risk_level,
          json.dumps(visual_flags), scan_id))
    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> dict | None:
    """Fetch a single scan by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def get_history(limit: int = 50) -> list:
    """Fetch recent scans."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_whois_cache(domain: str) -> dict | None:
    """Check WHOIS cache. Returns None if not cached or stale (>7 days)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM whois_cache WHERE domain = ?", (domain,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    # check if stale
    fetched = datetime.fromisoformat(row["fetched_at"])
    age = (datetime.utcnow() - fetched).days
    if age > 7:
        return None
    return dict(row)


def save_whois_cache(domain: str, age_days: int, registrar: str):
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO whois_cache
        (domain, age_days, registrar, fetched_at)
        VALUES (?, ?, ?, ?)
    """, (domain, age_days, registrar, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("flags", "eye1_result", "eye3_result", "shap_values"):
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d