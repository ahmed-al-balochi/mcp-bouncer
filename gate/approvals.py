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

    Production swap: nothing outside this class knows the storage engine, so
    SQLite can be replaced without touching the policy or the middleware.

    * DynamoDB -- grants become items keyed on `args_hash` with a native TTL
      attribute doing the expiry, and `consume` becomes a conditional
      `DeleteItem` on `attribute_exists(args_hash)`. The condition gives the same
      single-winner guarantee as the `DELETE ... WHERE` below.
    * Postgres -- `DELETE ... RETURNING` under READ COMMITTED, with a periodic
      sweep for expiry.

    Single-node SQLite is enough for this MVP but not for a horizontally scaled
    gate: the one-shot guarantee holds across processes on a shared file, not
    across hosts with separate files.
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

    def create(
        self, caller: str, tool: str, arguments: Mapping[str, Any]
    ) -> PendingApproval:
        """Park a call, reusing an existing pending row for an identical call."""
        digest = args_hash(caller, tool, arguments)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM pending WHERE args_hash = ? AND state = ?",
                (digest, PENDING),
            ).fetchone()
            if existing is not None:
                return _as_pending(existing)
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
                " state) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.caller,
                    record.tool,
                    record.arguments,
                    record.args_hash,
                    record.created_at,
                    record.state,
                ),
            )
            return record

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
                    self._clock() + self._ttl_seconds,
                ),
            )
            return _as_pending(row, state=APPROVED)

    def deny(self, approval_id: str) -> bool:
        with self._transaction() as connection:
            cursor = connection.execute(
                "UPDATE pending SET state = ? WHERE id = ? AND state = ?",
                (DENIED, approval_id, PENDING),
            )
            return cursor.rowcount == 1

    def consume(self, caller: str, tool: str, arguments: Mapping[str, Any]) -> bool:
        """Claim the grant for this exact call, at most once, ever.

        The claim is the `DELETE`: SQLite applies it inside a write transaction,
        so of any number of concurrent callers exactly one sees rowcount 1 and
        the row is gone before anyone else looks. A replayed call finds nothing.
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
        """Drop grants past their TTL and mark stale rows expired."""
        now = self._clock()
        with self._transaction() as connection:
            dropped = connection.execute(
                "DELETE FROM grants WHERE expires_at <= ?", (now,)
            ).rowcount
            connection.execute(
                "UPDATE pending SET state = ? WHERE state IN (?, ?) AND created_at <= ?",
                (EXPIRED, PENDING, APPROVED, now - self._ttl_seconds),
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
        finally:
            connection.close()

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


def _as_pending(row: sqlite3.Row, state: str | None = None) -> PendingApproval:
    return PendingApproval(
        id=row["id"],
        caller=row["caller"],
        tool=row["tool"],
        arguments=row["arguments"],
        args_hash=row["args_hash"],
        created_at=row["created_at"],
        state=state if state is not None else row["state"],
    )
