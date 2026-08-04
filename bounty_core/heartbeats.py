"""Reusable heartbeat/liveness primitives for Bounty Core stores.

A consuming module keeps the lease table in its own SQLite transaction, while
this module owns the schema and semantics. That preserves atomic state changes
(e.g. a hypothesis reclaim) without coupling unrelated modules to one global
coordinator database.
"""
from __future__ import annotations

import sqlite3
from typing import Any

HEARTBEAT_TABLE = "core_heartbeats"


def ensure_heartbeat_schema(conn: sqlite3.Connection) -> None:
    """Create the namespaced heartbeat table in a consumer-owned database."""
    conn.executescript(
        f"""
        CREATE TABLE IF NOT EXISTS {HEARTBEAT_TABLE} (
            namespace TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            heartbeat_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            PRIMARY KEY(namespace, subject_id, run_id)
        );
        CREATE INDEX IF NOT EXISTS idx_core_heartbeats_expiry
            ON {HEARTBEAT_TABLE}(namespace, expires_at);
        """
    )


def renew_heartbeat(
    conn: sqlite3.Connection,
    *,
    namespace: str,
    subject_id: str,
    run_id: str,
    ttl_seconds: int,
    now: float,
) -> dict[str, float]:
    """Renew one liveness lease and return its expiry metadata."""
    normalized_namespace = _required(namespace, "namespace")
    normalized_subject = _required(subject_id, "subject_id")
    normalized_run = _required(run_id, "run_id")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    timestamp = float(now)
    expires_at = timestamp + ttl_seconds
    conn.execute(
        f"""INSERT INTO {HEARTBEAT_TABLE}(namespace, subject_id, run_id, heartbeat_at, expires_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(namespace, subject_id, run_id) DO UPDATE SET
               heartbeat_at=excluded.heartbeat_at,
               expires_at=excluded.expires_at""",
        (normalized_namespace, normalized_subject, normalized_run, timestamp, expires_at),
    )
    return {"heartbeat_at": timestamp, "expires_at": expires_at}


def heartbeat_is_live(
    conn: sqlite3.Connection,
    *,
    namespace: str,
    subject_id: str,
    run_id: str,
    now: float,
) -> bool:
    """Return whether a namespaced subject/run lease is still unexpired."""
    row = conn.execute(
        f"SELECT expires_at FROM {HEARTBEAT_TABLE} WHERE namespace=? AND subject_id=? AND run_id=?",
        (_required(namespace, "namespace"), _required(subject_id, "subject_id"), _required(run_id, "run_id")),
    ).fetchone()
    if row is None:
        return False
    expires_at: Any = row["expires_at"] if isinstance(row, sqlite3.Row) else row[0]
    return float(expires_at) > float(now)


def _required(value: str, label: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    return normalized
