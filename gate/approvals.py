"""Pending approvals, one-shot grants and the rolling destructive counter."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

DEFAULT_DB_FILENAME = "bouncer.db"
DB_PATH_ENV = "BOUNCER_DB"
RATE_WINDOW_SECONDS = 3600

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
CONSUMED = "consumed"
EXPIRED = "expired"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending (
    id          TEXT PRIMARY KEY,
    caller      TEXT NOT NULL,
    tool        TEXT NOT NULL,
    arguments   TEXT NOT NULL,
    args_hash   TEXT NOT NULL,
    created_at  REAL NOT NULL,
    state       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS pending_by_state ON pending(state, args_hash);
CREATE TABLE IF NOT EXISTS grants (
    args_hash   TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL,
    caller      TEXT NOT NULL,
    tool        TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    caller      TEXT NOT NULL,
    tool        TEXT NOT NULL,
    released_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS releases_by_caller ON releases(caller, released_at);
"""


@dataclass(frozen=True)
class PendingApproval:
    id: str
    caller: str
    tool: str
    arguments: str
    args_hash: str
    created_at: float
    state: str
    # The grant's effective lifetime in seconds. On a row from `create` or
    # `list_pending` this is the stamped per-row TTL, or None for the store
    # default. On the record `approve` returns it is the resolved TTL used.
    ttl_seconds: float | None = None


def default_db_path() -> Path:
    override = os.environ.get(DB_PATH_ENV)
    if override:
        return Path(override)
    return Path.cwd() / DEFAULT_DB_FILENAME


def canonical_arguments(arguments: Mapping[str, Any]) -> str:
    """Serialise call arguments so that equal arguments always hash equally."""
    return json.dumps(dict(arguments), sort_keys=True, separators=(",", ":"))


def args_hash(caller: str, tool: str, arguments: Mapping[str, Any]) -> str:
    """Bind a grant to one caller, one tool and one exact set of arguments."""
    material = "\x00".join((caller, tool, canonical_arguments(arguments)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ApprovalStore:
    """The gate's approval state, behind a deliberately narrow interface.

    Nothing outside this class knows the storage engine, so SQLite can be
    swapped out. The one-shot guarantee holds on a shared file, not across hosts.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str] | None = None,
        *,
        ttl_minutes: int = 10,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = Path(db_path) if db_path is not None else default_db_path()
        self._ttl_seconds = float(ttl_minutes) * 60.0
        self._clock = clock
        self._create_schema()

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    def _effective_ttl(self, stored: float | None) -> float:
        """Resolve a row's stamped TTL, falling back to the store default.

        A None stored TTL means no stamped value, so it gets the baseline. This
        is the one place the fallback lives, so `approve` and `expire` agree.
        """
        return stored if stored is not None else self._ttl_seconds

    def create(
        self,
        caller: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        ttl_seconds: float | None = None,
    ) -> PendingApproval:
        """Park a call, reusing an existing pending row for an identical call.

        `ttl_seconds` is the caller's effective grant lifetime, stamped so
        `approve` and `expire` use it. On reuse the stored TTL is only tightened.
        """
        digest = args_hash(caller, tool, arguments)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM pending WHERE args_hash = ? AND state = ?",
                (digest, PENDING),
            ).fetchone()
            if existing is not None:
                self._tighten_pending_ttl(connection, existing, ttl_seconds)
                refreshed = connection.execute(
                    "SELECT * FROM pending WHERE id = ?", (existing["id"],)
                ).fetchone()
                return _as_pending(refreshed)
            record = PendingApproval(
                id=uuid.uuid4().hex[:12],
                caller=caller,
                tool=tool,
                arguments=canonical_arguments(arguments),
                args_hash=digest,
                created_at=self._clock(),
                state=PENDING,
            )
            connection.execute(
                "INSERT INTO pending (id, caller, tool, arguments, args_hash, created_at,"
                " state, ttl_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.caller,
                    record.tool,
                    record.arguments,
                    record.args_hash,
                    record.created_at,
                    record.state,
                    ttl_seconds,
                ),
            )
            return record

    def _tighten_pending_ttl(
        self,
        connection: sqlite3.Connection,
        existing: sqlite3.Row,
        incoming_ttl: float | None,
    ) -> None:
        """Lower a reused pending row's stored TTL to `incoming_ttl` if stricter.

        None means use the store default, so the row is left alone. We shorten
        only when `incoming_ttl` is less than what the row resolves to, never up.
        """
        if incoming_ttl is None:
            return
        stored = existing["ttl_seconds"]
        effective_stored = stored if stored is not None else self._ttl_seconds
        if incoming_ttl < effective_stored:
            connection.execute(
                "UPDATE pending SET ttl_seconds = ? WHERE id = ?",
                (incoming_ttl, existing["id"]),
            )

    def approve(self, approval_id: str) -> PendingApproval | None:
        """Grant one retry of the parked call. Returns None if there is nothing to grant."""
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM pending WHERE id = ? AND state = ?", (approval_id, PENDING)
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE pending SET state = ? WHERE id = ?", (APPROVED, approval_id)
            )
            # The grant's lifetime is the TTL stamped on the parked row (the
            # caller's effective TTL), not the store default. A row with no
            # stamped TTL falls back to the baseline.
            effective_ttl = self._effective_ttl(row["ttl_seconds"])
            connection.execute(
                "INSERT INTO grants (args_hash, approval_id, caller, tool, expires_at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(args_hash) DO UPDATE SET approval_id = excluded.approval_id,"
                " expires_at = excluded.expires_at",
                (
                    row["args_hash"],
                    approval_id,
                    row["caller"],
                    row["tool"],
                    self._clock() + effective_ttl,
                ),
            )
            return _as_pending(row, state=APPROVED, ttl_seconds=effective_ttl)

    def deny(self, approval_id: str) -> bool:
        with self._transaction() as connection:
            cursor = connection.execute(
                "UPDATE pending SET state = ? WHERE id = ? AND state = ?",
                (DENIED, approval_id, PENDING),
            )
            return cursor.rowcount == 1

    def consume(self, caller: str, tool: str, arguments: Mapping[str, Any]) -> bool:
        """Claim the grant for this exact call, at most once, ever.

        The claim is the `DELETE` inside a write transaction, so exactly one of
        any concurrent callers sees rowcount 1. A replayed call finds nothing.
        """
        digest = args_hash(caller, tool, arguments)
        now = self._clock()
        with self._transaction() as connection:
            claimed = connection.execute(
                "DELETE FROM grants WHERE args_hash = ? AND caller = ? AND tool = ?"
                " AND expires_at > ?",
                (digest, caller, tool, now),
            )
            if claimed.rowcount != 1:
                return False
            connection.execute(
                "INSERT INTO releases (caller, tool, released_at) VALUES (?, ?, ?)",
                (caller, tool, now),
            )
            connection.execute(
                "UPDATE pending SET state = ? WHERE args_hash = ? AND state = ?",
                (CONSUMED, digest, APPROVED),
            )
            return True

    def expire(self) -> int:
        """Drop grants past their TTL and mark stale rows expired.

        Grants carry an absolute `expires_at`, so sweeping is a simple compare.
        Pending rows are stale once `created_at + their own TTL <= now`.
        """
        now = self._clock()
        with self._transaction() as connection:
            dropped = connection.execute(
                "DELETE FROM grants WHERE expires_at <= ?", (now,)
            ).rowcount
            connection.execute(
                "UPDATE pending SET state = ? WHERE state IN (?, ?)"
                " AND created_at + COALESCE(ttl_seconds, ?) <= ?",
                (EXPIRED, PENDING, APPROVED, self._ttl_seconds, now),
            )
            return max(dropped, 0)

    def reset(self, caller: str) -> int:
        """Clear a caller's rolling destructive count after a human intervenes."""
        with self._transaction() as connection:
            cursor = connection.execute("DELETE FROM releases WHERE caller = ?", (caller,))
            return max(cursor.rowcount, 0)

    def list_pending(self) -> list[PendingApproval]:
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM pending WHERE state = ? ORDER BY created_at, id", (PENDING,)
            ).fetchall()
        return [_as_pending(row) for row in rows]

    def approved_in_window(
        self, caller: str, window_seconds: float = RATE_WINDOW_SECONDS
    ) -> int:
        cutoff = self._clock() - window_seconds
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM releases WHERE caller = ? AND released_at > ?",
                (caller, cutoff),
            ).fetchone()
        return int(row["total"])

    def _create_schema(self) -> None:
        # executescript() commits implicitly, so the schema is created outside
        # the explicit transaction wrapper the rest of the class uses.
        connection = self._connect()
        try:
            connection.executescript(_SCHEMA)
            self._migrate_pending_ttl(connection)
        finally:
            connection.close()

    def _migrate_pending_ttl(self, connection: sqlite3.Connection) -> None:
        # Per-row TTL migration. SQLite has no `ADD COLUMN IF NOT EXISTS`, so we
        # add the nullable column only when missing: idempotent and safe on every
        # boot. NULL means "no stamped TTL", read as the store default.
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(pending)").fetchall()
        }
        if "ttl_seconds" not in columns:
            connection.execute("ALTER TABLE pending ADD COLUMN ttl_seconds REAL")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()


def _as_pending(
    row: sqlite3.Row, state: str | None = None, ttl_seconds: float | None = None
) -> PendingApproval:
    # A given `ttl_seconds` overrides the row's stored value: this is how
    # `approve` reports the resolved grant lifetime even though the pending row
    # stored None. Otherwise the row's own stamped TTL is carried through.
    row_keys = row.keys()
    stored_ttl = row["ttl_seconds"] if "ttl_seconds" in row_keys else None
    return PendingApproval(
        id=row["id"],
        caller=row["caller"],
        tool=row["tool"],
        arguments=row["arguments"],
        args_hash=row["args_hash"],
        created_at=row["created_at"],
        state=state if state is not None else row["state"],
        ttl_seconds=ttl_seconds if ttl_seconds is not None else stored_ttl,
    )
