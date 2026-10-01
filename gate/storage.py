"""The storage seam: interfaces the gate depends on, and a factory to choose one.

Approvals and decisions sit behind `typing.Protocol`s, so a backend only has to
match the signatures. SQLite is the default; DynamoDB is opt-in.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from gate.approvals import PendingApproval
from gate.audit import AuditEntry

# Selection knobs. BOUNCER_-prefixed to match BOUNCER_DB and BOUNCER_POLICY.
STORE_ENV = "BOUNCER_STORE"
DYNAMODB_TABLE_ENV = "BOUNCER_DYNAMODB_TABLE"
DYNAMODB_AUDIT_TABLE_ENV = "BOUNCER_DYNAMODB_AUDIT_TABLE"

STORE_SQLITE = "sqlite"
STORE_DYNAMODB = "dynamodb"
DEFAULT_STORE = STORE_SQLITE


@runtime_checkable
class ApprovalStore(Protocol):
    """The approval state contract, identical for every backend.

    A grant is one-shot, bound to one caller + tool + exact arguments, and
    expires after `ttl_seconds`.
    """

    @property
    def ttl_seconds(self) -> float: ...

    def create(
        self,
        caller: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        ttl_seconds: float | None = None,
    ) -> PendingApproval: ...
    # `create` takes a per-approval `ttl_seconds` so the gate can stamp the
    # caller's effective TTL (a team may tighten it below the baseline) at
    # park time. `None` means use the store default, which is the baseline.

    def approve(self, approval_id: str) -> PendingApproval | None: ...

    def deny(self, approval_id: str) -> bool: ...

    def consume(self, caller: str, tool: str, arguments: Mapping[str, Any]) -> bool: ...

    def expire(self) -> int: ...

    def reset(self, caller: str) -> int: ...

    def list_pending(self) -> list[PendingApproval]: ...

    def approved_in_window(
        self, caller: str, window_seconds: float = ...
    ) -> int: ...


@runtime_checkable
class AuditLog(Protocol):
    """The decision-log contract: append and read, and nothing else.

    Append-only is part of the type: no update, delete, clear or truncate
    method. Each concrete class enforces it structurally or via IAM.
    """

    def record(
        self,
        caller: str,
        tool: str,
        classification: str,
        decision: str,
        args_hash: str,
    ) -> None: ...

    def entries(self, limit: int = ...) -> list[AuditEntry]: ...


def _selected_store() -> str:
    return os.environ.get(STORE_ENV, DEFAULT_STORE).strip().lower() or DEFAULT_STORE


def build_approval_store(
    *,
    db_path: str | os.PathLike[str] | None = None,
    ttl_minutes: int = 10,
    clock: Callable[[], float] | None = None,
) -> ApprovalStore:
    """Return the configured approval store, SQLite unless BOUNCER_STORE says otherwise.

    boto3 is imported only inside the DynamoDB branch, so the SQLite path never
    requires it.
    """
    backend = _selected_store()
    if backend == STORE_SQLITE:
        from gate.approvals import ApprovalStore as SqliteApprovalStore

        if clock is not None:
            return SqliteApprovalStore(db_path, ttl_minutes=ttl_minutes, clock=clock)
        return SqliteApprovalStore(db_path, ttl_minutes=ttl_minutes)
    if backend == STORE_DYNAMODB:
        from gate.dynamodb_approvals import DynamoDBApprovalStore

        table = _require_env(DYNAMODB_TABLE_ENV, backend)
        if clock is not None:
            return DynamoDBApprovalStore(table, ttl_minutes=ttl_minutes, clock=clock)
        return DynamoDBApprovalStore(table, ttl_minutes=ttl_minutes)
    raise ValueError(
        f"{STORE_ENV}={backend!r} is not a known backend; "
        f"use {STORE_SQLITE!r} or {STORE_DYNAMODB!r}"
    )


def build_audit_log(
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> AuditLog:
    """Return the configured audit log, matching the approval store's backend."""
    backend = _selected_store()
    if backend == STORE_SQLITE:
        from gate.audit import AuditLog as SqliteAuditLog

        return SqliteAuditLog(db_path)
    if backend == STORE_DYNAMODB:
        from gate.dynamodb_audit import DynamoDBAuditLog

        table = _require_env(DYNAMODB_AUDIT_TABLE_ENV, backend)
        return DynamoDBAuditLog(table)
    raise ValueError(
        f"{STORE_ENV}={backend!r} is not a known backend; "
        f"use {STORE_SQLITE!r} or {STORE_DYNAMODB!r}"
    )


def _require_env(name: str, backend: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{STORE_ENV}={backend!r} requires {name} to be set")
    return value
