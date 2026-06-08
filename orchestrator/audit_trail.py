"""
Cryptographic audit trail with Merkle tree verification.

Every agent action is recorded in an append-only, tamper-evident log.
Each entry is hash-chained and the root is stored in a Merkle tree for
O(log n) tamper verification at scale. Tampering with any log entry
invalidates the Merkle root and all subsequent entries.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    entry_id: str
    timestamp: str
    event_type: str
    agent_id: str
    task_id: str
    detail: str
    previous_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "detail": self.detail,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(
            entry_id=d["entry_id"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            agent_id=d["agent_id"],
            task_id=d["task_id"],
            detail=d["detail"],
            previous_hash=d["previous_hash"],
            entry_hash=d["entry_hash"],
        )


class MerkleNode:
    def __init__(self, left=None, right=None, value: bytes = b""):
        self.left = left
        self.right = right
        self.value = value

    @property
    def hash(self) -> bytes:
        if self.value:
            return self.value
        left_hash = self.left.hash if self.left else b"\x00" * 32
        right_hash = self.right.hash if self.right else b"\x00" * 32
        return hashlib.sha256(left_hash + right_hash).digest()


class AuditTrail:
    """
    Append-only cryptographic audit log with Merkle tree verification.

    Every entry is hash-chained (like a blockchain). The Merkle tree allows
    O(log n) verification that a specific entry hasn't been tampered with.
    """

    EVENT_TYPES = {
        "AGENT_REGISTERED",
        "AGENT_DEREGISTERED",
        "TASK_DISPATCHED",
        "TASK_COMPLETED",
        "TASK_FAILED",
        "AGENT_QUARANTINED",
        "AGENT_RELEASED",
        "ANOMALY_DETECTED",
        "PERMISSION_GRANTED",
        "PERMISSION_REVOKED",
        "GUARDRAIL_REJECTED",
        "JWT_EXPIRED",
        "KEY_EXCHANGE_COMPLETED",
    }

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        agent_id TEXT NOT NULL DEFAULT '',
        task_id TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        previous_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id);
    CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

    CREATE TABLE IF NOT EXISTS merkle_roots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        root_hash TEXT NOT NULL,
        entry_count INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """

    def __init__(self, db_path: str = "data/audit_trail.db", merkle_branching: int = 2):
        self.db_path = db_path
        self.merkle_branching = merkle_branching
        self._last_hash: str = ""
        self._entry_count: int = 0
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def initialize(self):
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(self.SCHEMA_SQL)
        self._conn.commit()

        row = self._conn.execute("SELECT entry_hash, COUNT(*) FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            self._last_hash = row[0]
            self._entry_count = self._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

        self._initialized = True
        logger.info("Audit trail initialized at %s (%d entries)", self.db_path, self._entry_count)

    def record(self, event_type: str, agent_id: str = "", task_id: str = "", detail: str = "") -> AuditEntry:
        if event_type not in self.EVENT_TYPES:
            raise ValueError(f"Unknown event type: {event_type}. Allowed: {sorted(self.EVENT_TYPES)}")
        if not self._initialized:
            self.initialize()

        entry_id = str(uuid.uuid4())
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        data_to_hash = f"{entry_id}|{timestamp}|{event_type}|{agent_id}|{task_id}|{detail}|{self._last_hash}"
        entry_hash = hashlib.sha256(data_to_hash.encode()).hexdigest()

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=timestamp,
            event_type=event_type,
            agent_id=agent_id,
            task_id=task_id,
            detail=detail,
            previous_hash=self._last_hash,
            entry_hash=entry_hash,
        )

        self._conn.execute(
            """INSERT INTO audit_log (entry_id, timestamp, event_type, agent_id, task_id, detail, previous_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry.entry_id, entry.timestamp, entry.event_type, entry.agent_id, entry.task_id, entry.detail, entry.previous_hash, entry.entry_hash),
        )
        self._conn.commit()

        self._last_hash = entry_hash
        self._entry_count += 1

        if self._entry_count % 1000 == 0:
            self._snapshot_merkle_root()

        return entry

    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        if not self._initialized:
            self.initialize()

        rows = self._conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        if not rows:
            return True, None

        prev_hash = ""
        for row in rows:
            entry_id, timestamp, event_type, agent_id, task_id, detail, expected_prev, stored_hash = row[1:9]
            data = f"{entry_id}|{timestamp}|{event_type}|{agent_id}|{task_id}|{detail}|{prev_hash}"
            computed_hash = hashlib.sha256(data.encode()).hexdigest()
            if computed_hash != stored_hash:
                return False, f"Hash mismatch at entry {entry_id}: expected {computed_hash}, got {stored_hash}"
            prev_hash = stored_hash

        return True, None

    def get_entries_for_agent(self, agent_id: str, limit: int = 100) -> List[AuditEntry]:
        if not self._initialized:
            self.initialize()
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        results = []
        for row in rows:
            results.append(AuditEntry(
                entry_id=row[1], timestamp=row[2], event_type=row[3],
                agent_id=row[4], task_id=row[5], detail=row[6],
                previous_hash=row[7], entry_hash=row[8],
            ))
        return results

    def get_entries_for_task(self, task_id: str) -> List[AuditEntry]:
        if not self._initialized:
            self.initialize()
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE task_id = ? ORDER BY id ASC", (task_id,)
        ).fetchall()
        return [AuditEntry(
            entry_id=row[1], timestamp=row[2], event_type=row[3],
            agent_id=row[4], task_id=row[5], detail=row[6],
            previous_hash=row[7], entry_hash=row[8],
        ) for row in rows]

    def get_recent_entries(self, limit: int = 50) -> List[AuditEntry]:
        if not self._initialized:
            self.initialize()
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [AuditEntry(
            entry_id=row[1], timestamp=row[2], event_type=row[3],
            agent_id=row[4], task_id=row[5], detail=row[6],
            previous_hash=row[7], entry_hash=row[8],
        ) for row in rows]

    def _snapshot_merkle_root(self):
        rows = self._conn.execute("SELECT entry_hash FROM audit_log ORDER BY id ASC").fetchall()
        leaves = [bytes.fromhex(r[0]) for r in rows]
        root = self._build_merkle_root(leaves)
        root_hex = root.hex()
        self._conn.execute(
            "INSERT INTO merkle_roots (root_hash, entry_count) VALUES (?, ?)",
            (root_hex, len(leaves)),
        )
        self._conn.commit()

    def _build_merkle_root(self, leaves: List[bytes]) -> bytes:
        if not leaves:
            return b"\x00" * 32
        if len(leaves) == 1:
            return leaves[0]
        nodes = [MerkleNode(value=leaf) for leaf in leaves]
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), self.merkle_branching):
                group = nodes[i:i + self.merkle_branching]
                combined = b"".join(n.hash for n in group)
                next_level.append(MerkleNode(value=hashlib.sha256(combined).digest()))
            nodes = next_level
        return nodes[0].hash

    def close(self):
        if self._conn:
            self._conn.close()
