"""The storage seam: interfaces the gate depends on, and a factory to choose one.

The gate does not care how approvals and decisions are stored -- only that a
store honours the one-shot, argument-bound, expiring-grant contract and that the
log only ever grows. Expressing that as a `typing.Protocol` rather than an ABC
means the existing SQLite classes satisfy it *structurally*, with no base class
to inherit and no registration step: a class is an `ApprovalStore` because it has
the right methods, not because it said so. A second backend then has exactly one
obligation -- match these signatures -- and the middleware, CLI and server never
learn which backend they hold.

The factory defaults to SQLite (R30) so local runs and the test suite stay
offline and fast; DynamoDB is opt-in through `BOUNCER_STORE`, mirroring the
existing `BOUNCER_DB` / `BOUNCER_POLICY` naming.
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

    This is the current public surface of the SQLite store, no more and no less.
    A grant is one-shot (claimed atomically, released at most once), bound to one
    caller + tool + exact arguments, and expires after `ttl_seconds`. R26 asks a
    DynamoDB backend to satisfy exactly this; if it cannot, that is a reported
    finding, not a silent widening of the interface.
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
    # R26 interface change (owner-approved, DECISIONS D5.5). `create` gains a
    # per-approval `ttl_seconds` so the gate can stamp the CALLER'S effective TTL
    # -- a team may have tightened it below the baseline (R23) -- on the parked
    # call at park time. `approve` then computes the grant's expiry from that
    # stored value, and `expire` honours it, instead of every grant living the
    # single store-wide default. Before this, the store was constructed once with
    # the baseline TTL and whichever process ran `approve` (usually the operator
    # CLI, which does not know the caller's team) wrote the expiry, so a team's
    # tightened TTL was advertised in the gate's message but never enforced on
    # the stored grant (bug D5.2). `None` means "use the store default", which
    # remains the baseline: existing callers keep working and a stamped TTL is
    # never looser than the baseline because a team override may only shorten it.

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

    Append-only is part of the type, not just the implementation: there is no
    update, delete, clear or truncate method to call. A backend that grew one
    would still type-check here, so each concrete class is additionally expected
    to enforce append-only structurally (SQLite) or through IAM (DynamoDB, R29).
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

    boto3 is imported only inside the DynamoDB branch (see the DynamoDB module),
    so importing this module, or running the entire SQLite path, never requires
    boto3 to be installed.
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
