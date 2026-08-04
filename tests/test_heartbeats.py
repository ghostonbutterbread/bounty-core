from __future__ import annotations

import sqlite3

from bounty_core.heartbeats import ensure_heartbeat_schema, heartbeat_is_live, renew_heartbeat


def test_heartbeats_are_namespaced_and_expire_independently():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ensure_heartbeat_schema(conn)

    renewed = renew_heartbeat(
        conn,
        namespace="hypothesis-owner",
        subject_id="agent-a",
        run_id="run-a",
        ttl_seconds=120,
        now=1_000.0,
    )

    assert renewed == {"heartbeat_at": 1_000.0, "expires_at": 1_120.0}
    assert heartbeat_is_live(conn, namespace="hypothesis-owner", subject_id="agent-a", run_id="run-a", now=1_119.0)
    assert not heartbeat_is_live(conn, namespace="mapstore-writer", subject_id="agent-a", run_id="run-a", now=1_119.0)
    assert not heartbeat_is_live(conn, namespace="hypothesis-owner", subject_id="agent-a", run_id="run-a", now=1_120.0)


def test_heartbeat_rejects_empty_identity_and_non_integer_ttl():
    import pytest

    conn = sqlite3.connect(":memory:")
    ensure_heartbeat_schema(conn)
    with pytest.raises(ValueError, match="namespace"):
        renew_heartbeat(conn, namespace="", subject_id="agent-a", run_id="run-a", ttl_seconds=1, now=1.0)
    with pytest.raises(ValueError, match="positive integer"):
        renew_heartbeat(conn, namespace="hypothesis-owner", subject_id="agent-a", run_id="run-a", ttl_seconds=0.5, now=1.0)
