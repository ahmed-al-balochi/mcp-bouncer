"""Append-only record of every decision the gate made."""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from gate.approvals import default_db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at    REAL NOT NULL,
    caller         TEXT NOT NULL,
    tool           TEXT NOT NULL,
    classification TEXT NOT NULL,
    decision       TEXT NOT NULL,
    args_hash      TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class AuditEntry:
    recorded_at: float
    caller: str
    tool: str
    classification: str
    decision: str
    args_hash: str

    @property
    def timestamp(self) -> str:
        return datetime.fromtimestamp(self.recorded_at, tz=timezone.utc).isoformat(
            timespec="seconds"
        )


class AuditLog:
    """The decision log, in the same SQLite database as the approvals.

    Append-only is enforced structurally rather than by permissions: this class
    only ever issues INSERT and SELECT, and exposes no update or delete method.
    """

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self._path = Path(db_path) if db_path is not None else default_db_path()
        connection = sqlite3.connect(self._path, timeout=30.0)
        try:
            connection.executescript(_SCHEMA)
        finally:
            connection.close()

    def record(
        self,
        caller: str,
        tool: str,
        classification: str,
        decision: str,
        args_hash: str,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO audit (recorded_at, caller, tool, classification, decision,"
                " args_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), caller, tool, classification, decision, args_hash),
            )

    def entries(self, limit: int = 100) -> list[AuditEntry]:
        """Return the most recent entries, oldest first."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            AuditEntry(
                recorded_at=row["recorded_at"],
                caller=row["caller"],
                tool=row["tool"],
                classification=row["classification"],
                decision=row["decision"],
                args_hash=row["args_hash"],
            )
            for row in reversed(rows)
        ]

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
            with connection:
                yield connection
        finally:
            connection.close()
