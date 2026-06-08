"""
Behavioral metrics logger for per-agent session tracking.

Collects and persists metrics for anomaly detection training and real-time scoring.
Uses SQLite via aiosqlite for async-friendly storage.
"""

from __future__ import annotations

import os
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import aiosqlite

logger = logging.getLogger(__name__)


@dataclass
class MetricEntry:
    agent_id: str
    task_id: str
    timestamp: str
    payload_bytes: int
    latency_us: float
    error_code: str
    anomaly_score: float = 0.0
    permission_boundary: List[str] = field(default_factory=list)
    task_type: str = ""
    session_id: str = ""


class BehavioralLogger:
    """Persist and query agent behavioral metrics for anomaly detection."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS behavioral_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        session_id TEXT DEFAULT '',
        timestamp TEXT NOT NULL,
        payload_bytes INTEGER NOT NULL DEFAULT 0,
        latency_us REAL NOT NULL DEFAULT 0.0,
        error_code TEXT DEFAULT '',
        anomaly_score REAL NOT NULL DEFAULT 0.0,
        task_type TEXT DEFAULT '',
        permission_boundary TEXT DEFAULT '[]',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_metrics_agent_id
        ON behavioral_metrics(agent_id);

    CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
        ON behavioral_metrics(timestamp);

    CREATE INDEX IF NOT EXISTS idx_metrics_session
        ON behavioral_metrics(session_id);

    CREATE TABLE IF NOT EXISTS anomaly_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        task_id TEXT DEFAULT '',
        anomaly_level TEXT NOT NULL,
        score REAL NOT NULL,
        detector_name TEXT NOT NULL,
        detail TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """

    def __init__(self, db_path: str = "data/behavioral_metrics.db"):
        self.db_path = db_path
        self._initialized = False

    async def initialize(self):
        """Create tables and indexes if they don't exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(self.SCHEMA_SQL)
            await db.commit()
        self._initialized = True
        logger.info("Behavioral logger initialized at %s", self.db_path)

    async def log_metric(
        self, agent_id: str, task_id: str, payload_bytes: int, latency_us: float, error_code: str = ""
    ):
        entry = MetricEntry(
            agent_id=agent_id, task_id=task_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            payload_bytes=payload_bytes, latency_us=latency_us, error_code=error_code,
        )
        await self.log(entry)

    async def log(self, entry: MetricEntry):
        """Persist a single behavioral metric entry."""
        if not self._initialized:
            await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO behavioral_metrics
                   (agent_id, task_id, session_id, timestamp, payload_bytes,
                    latency_us, error_code, anomaly_score, task_type, permission_boundary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.agent_id,
                    entry.task_id,
                    entry.session_id,
                    entry.timestamp,
                    entry.payload_bytes,
                    entry.latency_us,
                    entry.error_code,
                    entry.anomaly_score,
                    entry.task_type,
                    json.dumps(entry.permission_boundary),
                ),
            )
            await db.commit()

    async def log_anomaly_event(
        self,
        agent_id: str,
        anomaly_level: str,
        score: float,
        detector_name: str,
        task_id: str = "",
        detail: str = "",
    ):
        """Log an anomaly detection event."""
        if not self._initialized:
            await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """INSERT INTO anomaly_events
                   (agent_id, task_id, anomaly_level, score, detector_name, detail)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (agent_id, task_id, anomaly_level, score, detector_name, detail),
            )
            await db.commit()

    async def get_recent_metrics(
        self, agent_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve the most recent metrics for a specific agent."""
        if not self._initialized:
            await self.initialize()

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """SELECT * FROM behavioral_metrics
                   WHERE agent_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (agent_id, limit),
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_feature_vector(
        self, agent_id: str, window_seconds: float = 10.0
    ) -> List[float]:
        """
        Extract feature vector for anomaly scoring:
        [message_frequency, avg_payload_size, avg_latency, error_rate, payload_variance]
        """
        if not self._initialized:
            await self.initialize()

        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - window_seconds),
        )

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """SELECT
                    COUNT(*) as msg_count,
                    AVG(payload_bytes) as avg_payload,
                    AVG(latency_us) as avg_latency,
                    SUM(CASE WHEN error_code != '' THEN 1 ELSE 0 END) as error_count
                 FROM behavioral_metrics
                 WHERE agent_id = ? AND timestamp >= ?""",
                (agent_id, cutoff),
            )
            row = await cursor.fetchone()

        if row is None or row[0] == 0:
            return [0.0, 0.0, 0.0, 0.0, 0.0]

        msg_count = float(row[0])
        avg_payload = row[1] or 0.0
        avg_latency = row[2] or 0.0
        error_count = float(row[3])
        error_rate = error_count / msg_count if msg_count > 0 else 0.0

        frequency = msg_count / window_seconds

        return [frequency, avg_payload, avg_latency, error_rate, 0.0]
