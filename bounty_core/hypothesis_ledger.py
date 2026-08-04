"""Private-first, heartbeat-backed hypothesis coordination for BBH lanes.

The store preserves an agent's in-progress ideas without feeding them into other
agents' context.  An unresolved hypothesis becomes discoverable only after its
owner's native heartbeat expires.  This is coordination metadata, not a source
of target facts: callers link factual observations to MapStore separately.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .heartbeats import ensure_heartbeat_schema, heartbeat_is_live, renew_heartbeat
from .storage import normalize_family, normalize_lane, normalize_program, resolve_storage

DEFAULT_TTL_SECONDS = 2 * 60 * 60
HEARTBEAT_NAMESPACE = "hypothesis-owner"
UNRESOLVED_STATUSES = {"candidate", "active", "queued", "blocked", "deferred"}
TERMINAL_STATUSES = {"completed", "disproved", "retired", "combined"}
VALID_STATUSES = UNRESOLVED_STATUSES | TERMINAL_STATUSES


class HypothesisLedger:
    """A lane-local ledger with private owner views and expired recovery views."""

    def __init__(
        self,
        program: str,
        *,
        family: str = "web_bounty",
        lane: str = "web",
        root_override: str | Path | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive integer")
        self.program = normalize_program(program)
        self.family = normalize_family(family)
        self.lane = normalize_lane(lane)
        self.ttl_seconds = int(ttl_seconds)
        self._now = now or time.time
        self._layout = resolve_storage(
            self.program,
            family=self.family,
            lane=self.lane,
            root_override=root_override,
            create=False,
        )
        self.root = self._layout.lane_root / "hypotheses"
        self.db_path = self.root / "hypothesis_ledger.sqlite"
        self.events_path = self.root / "events.jsonl"

    def create(
        self,
        *,
        agent_id: str,
        run_id: str,
        title: str,
        surface: str,
        tags: Iterable[str],
        url: str | None = None,
        parent_id: str | None = None,
        expected_chain: str | None = None,
        next_discriminator: str | None = None,
        evidence_refs: Iterable[str] = (),
        status: str = "candidate",
    ) -> dict[str, Any]:
        normalized_status = _status(status)
        if normalized_status not in UNRESOLVED_STATUSES:
            raise ValueError("new hypotheses must start unresolved")
        title = _required(title, "title")
        surface = _required(surface, "surface")
        timestamp = self._now()
        record_id = f"H-{uuid.uuid4().hex[:12]}"
        payload = {
            "id": record_id,
            "parent_id": _optional(parent_id),
            "title": title,
            "surface": surface,
            "url": normalize_url(url or ""),
            "tags": _tags(tags),
            "expected_chain": _optional(expected_chain),
            "next_discriminator": _optional(next_discriminator),
            "evidence_refs": _strings(evidence_refs),
            "status": normalized_status,
            "owner_agent_id": _required(agent_id, "agent_id"),
            "owner_run_id": _required(run_id, "run_id"),
            "created_at": timestamp,
            "updated_at": timestamp,
            "completed_at": None,
        }
        with self._connection() as conn:
            self._init(conn)
            conn.execute("BEGIN IMMEDIATE")
            if parent_id:
                parent = self._row(conn, parent_id)
                if parent is None:
                    raise KeyError(f"parent hypothesis not found: {parent_id}")
                parent_item = _row_payload(parent)
                if (
                    parent_item["owner_agent_id"] != agent_id
                    or parent_item["owner_run_id"] != run_id
                    or not self._owner_live(conn, agent_id, run_id, timestamp)
                ):
                    raise PermissionError("only a live parent owner may create a child hypothesis")
            self._heartbeat(conn, agent_id, run_id, timestamp)
            conn.execute(
                """
                INSERT INTO hypotheses(
                    id, parent_id, title, surface, url, tags_json, expected_chain,
                    next_discriminator, evidence_refs_json, status, owner_agent_id,
                    owner_run_id, created_at, updated_at, completed_at
                ) VALUES(:id, :parent_id, :title, :surface, :url, :tags_json,
                    :expected_chain, :next_discriminator, :evidence_refs_json,
                    :status, :owner_agent_id, :owner_run_id, :created_at,
                    :updated_at, :completed_at)
                """,
                {**payload, "tags_json": json.dumps(payload["tags"]), "evidence_refs_json": json.dumps(payload["evidence_refs"])},
            )
            self._event(conn, "created", record_id, agent_id, run_id, timestamp)
            conn.commit()
        return self._with_visibility(payload, viewer_agent_id=agent_id, viewer_run_id=run_id, timestamp=timestamp, owner_live=True)

    def heartbeat(self, *, agent_id: str, run_id: str) -> dict[str, Any]:
        timestamp = self._now()
        with self._connection() as conn:
            self._init(conn)
            conn.execute("BEGIN IMMEDIATE")
            self._heartbeat(conn, agent_id, run_id, timestamp)
            self._event(conn, "heartbeat", None, agent_id, run_id, timestamp)
            conn.commit()
        return {"agent_id": agent_id, "run_id": run_id, "heartbeat_at": timestamp, "expires_at": timestamp + self.ttl_seconds}

    def list_visible(
        self,
        *,
        agent_id: str,
        run_id: str,
        url: str | None = None,
        surface: str | None = None,
        tags: Iterable[str] = (),
        statuses: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        timestamp = self._now()
        required_tags = set(_tags(tags))
        normalized_url = normalize_url(url or "")
        has_recovery_scope = bool(normalized_url or surface or required_tags)
        requested_statuses = {_status(item) for item in statuses} if statuses is not None else UNRESOLVED_STATUSES
        with self._connection() as conn:
            self._init(conn)
            rows = conn.execute("SELECT * FROM hypotheses WHERE status IN ({}) ORDER BY created_at, id".format(",".join("?" for _ in requested_statuses)), tuple(sorted(requested_statuses))).fetchall()
            result = []
            for row in rows:
                item = _row_payload(row)
                owner_live = self._owner_live(conn, item["owner_agent_id"], item["owner_run_id"], timestamp)
                is_owner = item["owner_agent_id"] == agent_id and item["owner_run_id"] == run_id
                if not is_owner and (
                    owner_live
                    or item["status"] not in UNRESOLVED_STATUSES
                    or not has_recovery_scope
                ):
                    continue
                if normalized_url and item["url"] != normalized_url:
                    continue
                if surface and item["surface"] != surface:
                    continue
                if required_tags and not required_tags.issubset(set(item["tags"])):
                    continue
                result.append(self._with_visibility(item, viewer_agent_id=agent_id, viewer_run_id=run_id, timestamp=timestamp, owner_live=owner_live))
            return result

    def continuation_state(self, *, agent_id: str, run_id: str, surface: str | None = None) -> dict[str, Any]:
        private = self.list_visible(agent_id=agent_id, run_id=run_id, surface=surface)
        owned = [item for item in private if item["visibility"] == "private"]
        return {
            "private_unresolved_count": len(owned),
            "active_count": sum(item["status"] == "active" for item in owned),
            "surface": surface,
        }

    def reclaim(self, hypothesis_id: str, *, agent_id: str, run_id: str) -> dict[str, Any]:
        timestamp = self._now()
        with self._connection() as conn:
            self._init(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, hypothesis_id)
            if row is None:
                raise KeyError(f"hypothesis not found: {hypothesis_id}")
            item = _row_payload(row)
            if item["status"] not in UNRESOLVED_STATUSES:
                raise ValueError(f"hypothesis is terminal: {item['status']}")
            if self._owner_live(conn, item["owner_agent_id"], item["owner_run_id"], timestamp):
                raise PermissionError("hypothesis is still private to a live owner")
            self._heartbeat(conn, agent_id, run_id, timestamp)
            conn.execute(
                "UPDATE hypotheses SET owner_agent_id=?, owner_run_id=?, status='active', updated_at=? WHERE id=?",
                (agent_id, run_id, timestamp, hypothesis_id),
            )
            self._event(conn, "reclaimed", hypothesis_id, agent_id, run_id, timestamp, previous_owner=item["owner_agent_id"])
            conn.commit()
            updated_row = self._row(conn, hypothesis_id)
            assert updated_row is not None
            updated = _row_payload(updated_row)
        return self._with_visibility(updated, viewer_agent_id=agent_id, viewer_run_id=run_id, timestamp=timestamp, owner_live=True)

    def delegate(
        self,
        hypothesis_id: str,
        *,
        agent_id: str,
        run_id: str,
        child_agent_id: str,
        child_run_id: str,
    ) -> dict[str, Any]:
        """Transfer one owned hypothesis branch to one explicit child agent.

        Delegation grants the child only this branch; it never reveals the
        parent agent's other private candidates.
        """
        timestamp = self._now()
        with self._connection() as conn:
            self._init(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, hypothesis_id)
            if row is None:
                raise KeyError(f"hypothesis not found: {hypothesis_id}")
            item = _row_payload(row)
            if item["status"] not in UNRESOLVED_STATUSES:
                raise ValueError(f"hypothesis is terminal: {item['status']}")
            if item["owner_agent_id"] != agent_id or item["owner_run_id"] != run_id:
                raise PermissionError("only the current owner may delegate a hypothesis")
            if not self._owner_live(conn, agent_id, run_id, timestamp):
                raise PermissionError("stale owners cannot delegate; reclaim the hypothesis first")
            self._heartbeat(conn, child_agent_id, child_run_id, timestamp)
            conn.execute(
                "UPDATE hypotheses SET owner_agent_id=?, owner_run_id=?, status='active', updated_at=? WHERE id=?",
                (child_agent_id, child_run_id, timestamp, hypothesis_id),
            )
            self._event(conn, "delegated", hypothesis_id, child_agent_id, child_run_id, timestamp, parent_agent_id=agent_id, parent_run_id=run_id)
            conn.commit()
            updated_row = self._row(conn, hypothesis_id)
            assert updated_row is not None
            updated = _row_payload(updated_row)
        return self._with_visibility(updated, viewer_agent_id=child_agent_id, viewer_run_id=child_run_id, timestamp=timestamp, owner_live=True)

    def complete(self, hypothesis_id: str, *, agent_id: str, run_id: str, status: str = "completed") -> dict[str, Any]:
        terminal_status = _status(status)
        if terminal_status not in TERMINAL_STATUSES:
            raise ValueError("completion requires a terminal status")
        timestamp = self._now()
        with self._connection() as conn:
            self._init(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, hypothesis_id)
            if row is None:
                raise KeyError(f"hypothesis not found: {hypothesis_id}")
            item = _row_payload(row)
            if item["owner_agent_id"] != agent_id or item["owner_run_id"] != run_id:
                raise PermissionError("only the current owner may complete a hypothesis")
            if not self._owner_live(conn, agent_id, run_id, timestamp):
                raise PermissionError("stale owners cannot complete; reclaim the hypothesis first")
            conn.execute("UPDATE hypotheses SET status=?, updated_at=?, completed_at=? WHERE id=?", (terminal_status, timestamp, timestamp, hypothesis_id))
            self._event(conn, "completed", hypothesis_id, agent_id, run_id, timestamp, status=terminal_status)
            conn.commit()
            updated_row = self._row(conn, hypothesis_id)
            assert updated_row is not None
            updated = _row_payload(updated_row)
        return self._with_visibility(updated, viewer_agent_id=agent_id, viewer_run_id=run_id, timestamp=timestamp, owner_live=True)

    def _connection(self) -> sqlite3.Connection:
        self.root.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                parent_id TEXT REFERENCES hypotheses(id),
                title TEXT NOT NULL,
                surface TEXT NOT NULL,
                url TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL,
                expected_chain TEXT,
                next_discriminator TEXT,
                evidence_refs_json TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_agent_id TEXT NOT NULL,
                owner_run_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                completed_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_hypotheses_owner ON hypotheses(owner_agent_id, owner_run_id, status);
            CREATE INDEX IF NOT EXISTS idx_hypotheses_url ON hypotheses(url, surface, status);
            CREATE TABLE IF NOT EXISTS hypothesis_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                hypothesis_id TEXT,
                agent_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                occurred_at REAL NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )
        ensure_heartbeat_schema(conn)
        self._migrate_legacy_heartbeats(conn)

    @staticmethod
    def _migrate_legacy_heartbeats(conn: sqlite3.Connection) -> None:
        legacy = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_heartbeats'"
        ).fetchone()
        if legacy is None:
            return
        rows = conn.execute(
            "SELECT agent_id, run_id, heartbeat_at, expires_at FROM agent_heartbeats"
        ).fetchall()
        for row in rows:
            conn.execute(
                """INSERT INTO core_heartbeats(namespace, subject_id, run_id, heartbeat_at, expires_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(namespace, subject_id, run_id) DO UPDATE SET
                     heartbeat_at=MAX(core_heartbeats.heartbeat_at, excluded.heartbeat_at),
                     expires_at=MAX(core_heartbeats.expires_at, excluded.expires_at)""",
                (HEARTBEAT_NAMESPACE, row[0], row[1], row[2], row[3]),
            )
        conn.execute("DROP TABLE agent_heartbeats")

    def _heartbeat(self, conn: sqlite3.Connection, agent_id: str, run_id: str, timestamp: float) -> None:
        renew_heartbeat(
            conn,
            namespace=HEARTBEAT_NAMESPACE,
            subject_id=agent_id,
            run_id=run_id,
            ttl_seconds=self.ttl_seconds,
            now=timestamp,
        )

    def _owner_live(self, conn: sqlite3.Connection, agent_id: str, run_id: str, timestamp: float) -> bool:
        return heartbeat_is_live(
            conn,
            namespace=HEARTBEAT_NAMESPACE,
            subject_id=agent_id,
            run_id=run_id,
            now=timestamp,
        )

    @staticmethod
    def _row(conn: sqlite3.Connection, hypothesis_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone()

    def _event(self, conn: sqlite3.Connection, event: str, hypothesis_id: str | None, agent_id: str, run_id: str, timestamp: float, **payload: Any) -> None:
        conn.execute(
            "INSERT INTO hypothesis_events(event, hypothesis_id, agent_id, run_id, occurred_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
            (event, hypothesis_id, agent_id, run_id, timestamp, json.dumps(payload, sort_keys=True)),
        )

    @staticmethod
    def _with_visibility(item: dict[str, Any], *, viewer_agent_id: str, viewer_run_id: str, timestamp: float, owner_live: bool) -> dict[str, Any]:
        result = dict(item)
        is_owner = item["owner_agent_id"] == viewer_agent_id and item["owner_run_id"] == viewer_run_id
        result["visibility"] = "private" if is_owner else "reclaimable"
        result["owner_live"] = owner_live
        return result


def normalize_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError(f"invalid URL: {value!r}")
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    path = parts.path.rstrip("/") or "/"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme.lower() or "https", netloc, path, query, ""))


def _row_payload(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"], "parent_id": row["parent_id"], "title": row["title"], "surface": row["surface"],
        "url": row["url"], "tags": json.loads(row["tags_json"]), "expected_chain": row["expected_chain"],
        "next_discriminator": row["next_discriminator"], "evidence_refs": json.loads(row["evidence_refs_json"]),
        "status": row["status"], "owner_agent_id": row["owner_agent_id"], "owner_run_id": row["owner_run_id"],
        "created_at": row["created_at"], "updated_at": row["updated_at"], "completed_at": row["completed_at"],
    }


def _required(value: str, label: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        raise ValueError(f"{label} is required")
    return cleaned


def _optional(value: str | None) -> str | None:
    cleaned = str(value or "").strip()
    return cleaned or None


def _status(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized not in VALID_STATUSES:
        raise ValueError(f"invalid hypothesis status: {value!r}")
    return normalized


def _strings(values: Iterable[str]) -> list[str]:
    return [item for item in dict.fromkeys(str(value).strip() for value in values if str(value).strip())]


def _tags(values: Iterable[str]) -> list[str]:
    return sorted({str(value).strip().lower().replace("_", "-") for value in values if str(value).strip()})
