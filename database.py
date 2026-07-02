"""
PRAHARI AI — SQLite Persistence Layer
Async SQLite via aiosqlite. All tables are created on startup.
Stores: sessions, alerts, reports, audit_log, geo_incidents (live)

Tables:
  sessions       — every /classify call with verdict + metadata
  alerts         — MHA-style alerts generated from high-risk sessions
  reports        — citizen-submitted reports (geo-tagged)
  audit_log      — tamper-evident chain (from audit_log.py)
  live_incidents — real-time geo incidents from classify calls
"""
import os
import json
import hashlib
import aiosqlite
from datetime import datetime, timezone

DB_PATH = os.getenv("DATABASE_PATH", "prahari.db")


def _now():
    return datetime.now(timezone.utc).isoformat()


async def init_db():
    """Create all tables if they don't exist. Called once at startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,
            timestamp   TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            confidence  INTEGER NOT NULL,
            scam_type   TEXT,
            channel     TEXT,
            district    TEXT,
            source      TEXT,
            advice      TEXT,
            language    TEXT DEFAULT 'en',
            raw_json    TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          TEXT PRIMARY KEY,
            session_id  TEXT,
            alert_type  TEXT NOT NULL,
            risk_score  INTEGER,
            verdict     TEXT,
            district    TEXT,
            status      TEXT DEFAULT 'SENT',
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          TEXT PRIMARY KEY,
            session_id  TEXT,
            district    TEXT,
            lat         REAL,
            lon         REAL,
            incident_type TEXT DEFAULT 'fraud_complaint',
            severity    INTEGER DEFAULT 2,
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            seq         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            metadata    TEXT,
            hash        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS live_incidents (
            id          TEXT PRIMARY KEY,
            district    TEXT,
            lat         REAL,
            lon         REAL,
            incident_type TEXT,
            severity    INTEGER,
            date        TEXT,
            timestamp   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_reports_district ON reports(district);
        CREATE INDEX IF NOT EXISTS idx_live_incidents_date ON live_incidents(date);
        """)
        await db.commit()


# ── Sessions ──────────────────────────────────────────────────────────────────

async def save_session(session: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO sessions
            (id, timestamp, verdict, confidence, scam_type, channel, district, source, advice, language, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.get("session_id"),
            session.get("timestamp", _now()),
            session.get("verdict"),
            session.get("confidence", 0),
            session.get("scam_type", session.get("rule_based", {}).get("verdict")),
            session.get("channel"),
            session.get("district"),
            session.get("source"),
            session.get("advice", "")[:500],
            session.get("language", "en"),
            json.dumps(session),
        ))
        await db.commit()


async def get_sessions(limit: int = 50, verdict_filter: str = None):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if verdict_filter:
            cur = await db.execute(
                "SELECT * FROM sessions WHERE verdict=? ORDER BY timestamp DESC LIMIT ?",
                (verdict_filter, limit)
            )
        else:
            cur = await db.execute(
                "SELECT * FROM sessions ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def count_sessions():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM sessions")
        row = await cur.fetchone()
        return row[0] if row else 0


async def count_scams():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT COUNT(*) FROM sessions WHERE verdict IN ('SCAM_LIKELY', 'SUSPICIOUS')"
        )
        row = await cur.fetchone()
        return row[0] if row else 0


# ── Alerts ───────────────────────────────────────────────────────────────────

async def save_alert(alert: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO alerts
            (id, session_id, alert_type, risk_score, verdict, district, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("alert_id"),
            alert.get("session_id"),
            alert.get("type", "MHA_ALERT"),
            alert.get("risk_score", 0),
            alert.get("verdict"),
            alert.get("district"),
            alert.get("status", "SENT"),
            alert.get("timestamp", _now()),
        ))
        await db.commit()


async def get_alerts(limit: int = 50):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def count_alerts():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM alerts")
        row = await cur.fetchone()
        return row[0] if row else 0


# ── Live Incidents ────────────────────────────────────────────────────────────

async def save_live_incident(inc: dict):
    import uuid
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO live_incidents
            (id, district, lat, lon, incident_type, severity, date, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4())[:8],
            inc.get("district", "unknown"),
            inc.get("lat"),
            inc.get("lon"),
            inc.get("type", "fraud_complaint"),
            inc.get("severity", 2),
            inc.get("date", _now()[:10]),
            _now(),
        ))
        await db.commit()


async def get_live_incidents(limit: int = 500):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM live_incidents ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


# ── Audit Log ─────────────────────────────────────────────────────────────────

async def persist_audit_event(event: dict):
    """Persist an audit event (from audit_log.py) into SQLite."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO audit_log (timestamp, event_type, metadata, hash)
            VALUES (?, ?, ?, ?)
        """, (
            event.get("timestamp", _now()),
            event.get("event_type"),
            json.dumps(event.get("metadata", {})),
            event.get("hash", ""),
        ))
        await db.commit()


async def get_audit_log(limit: int = 100):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


# ── Dashboard Summary ─────────────────────────────────────────────────────────

async def get_dashboard_counts():
    """Returns real counts from the database for the KPI cards."""
    async with aiosqlite.connect(DB_PATH) as db:
        total_sessions = (await (await db.execute("SELECT COUNT(*) FROM sessions")).fetchone())[0]
        scams_detected = (await (await db.execute(
            "SELECT COUNT(*) FROM sessions WHERE verdict='SCAM_LIKELY'"
        )).fetchone())[0]
        suspicious = (await (await db.execute(
            "SELECT COUNT(*) FROM sessions WHERE verdict='SUSPICIOUS'"
        )).fetchone())[0]
        alerts_sent = (await (await db.execute("SELECT COUNT(*) FROM alerts")).fetchone())[0]
        live_reports = (await (await db.execute("SELECT COUNT(*) FROM live_incidents")).fetchone())[0]

        # 7-day trend: sessions per day
        trend_rows = await (await db.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as cnt
            FROM sessions
            WHERE timestamp >= DATE('now', '-7 days')
            GROUP BY day ORDER BY day
        """)).fetchall()

        return {
            "total_sessions": total_sessions,
            "scams_detected": scams_detected,
            "suspicious": suspicious,
            "alerts_sent": alerts_sent,
            "live_reports": live_reports,
            "trend_7day": [{"day": r[0], "count": r[1]} for r in trend_rows],
        }
