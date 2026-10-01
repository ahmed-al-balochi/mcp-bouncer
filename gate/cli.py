"""The human side of the gate: inspect what is parked, and act on it."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from typing import Sequence

from gate.registry import PolicyConfigError, load_registry
from gate.storage import (
    STORE_ENV,
    ApprovalStore,
    AuditLog,
    build_approval_store,
    build_audit_log,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)

    try:
        registry = load_registry(arguments.policy)
    except PolicyConfigError as error:
        print(f"bouncer: {error}")
        return 2

    # Build through the factory so the operator acts on whichever store the
    # deployed gate uses. Only construction sits inside the try: a bad
    # backend is a one-line operator error, but a failure doing the work is not.
    try:
        if arguments.command == "log":
            audit = build_audit_log(db_path=arguments.db)
        else:
            approvals = build_approval_store(
                db_path=arguments.db, ttl_minutes=registry.limits.approval_ttl_minutes
            )
    except (ValueError, RuntimeError) as error:
        print(f"bouncer: {error}")
        return 2

    if arguments.command == "log":
        return _log(audit, arguments.limit)
    if arguments.command == "list":
        return _list(approvals)
    if arguments.command == "approve":
        return _approve(approvals, arguments.approval_id, registry.limits.approval_ttl_minutes)
    if arguments.command == "deny":
        return _deny(approvals, arguments.approval_id)
    return _reset(approvals, arguments.caller)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bouncer", description="Inspect and act on mcp-bouncer approvals."
    )
    parser.add_argument(
        "--db",
        default=None,
        help=f"gate database for the SQLite backend (default: $BOUNCER_DB or ./bouncer.db); ignored when ${STORE_ENV} selects another backend",
    )
    parser.add_argument(
        "--policy", default=None, help="policy.yaml (default: $BOUNCER_POLICY or ./policy.yaml)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="show parked calls awaiting a decision")
    approve = commands.add_parser("approve", help="release one parked call for one retry")
    approve.add_argument("approval_id")
    deny = commands.add_parser("deny", help="refuse a parked call")
    deny.add_argument("approval_id")
    reset = commands.add_parser("reset", help="clear a caller's destructive rate limit")
    reset.add_argument("caller")
    log = commands.add_parser("log", help="print the decision log")
    log.add_argument("--limit", type=int, default=50)
    return parser


def _list(approvals: ApprovalStore) -> int:
    approvals.expire()
    pending = approvals.list_pending()
    if not pending:
        print("no parked calls")
        return 0
    print(f"{'ID':<14}{'CALLER':<16}{'TOOL':<20}{'PARKED (UTC)':<22}ARGUMENTS")
    for record in pending:
        print(
            f"{record.id:<14}{record.caller:<16}{record.tool:<20}"
            f"{_stamp(record.created_at):<22}{record.arguments}"
        )
    return 0


def _approve(approvals: ApprovalStore, approval_id: str, ttl_minutes: int) -> int:
    approvals.expire()
    granted = approvals.approve(approval_id)
    if granted is None:
        print(f"bouncer: no parked call with id {approval_id}")
        return 1
    # Print the grant's real lifetime from the row the store just wrote, not the
    # CLI's baseline: the gate stamped the caller's effective TTL at park time.
    # A row with no stamped TTL falls back to the store default.
    lifetime_minutes = (
        granted.ttl_seconds / 60.0 if granted.ttl_seconds is not None else ttl_minutes
    )
    print(
        f"approved {approval_id}: {granted.tool} for {granted.caller}."
        f" Valid for one retry of {granted.arguments} within"
        f" {_format_minutes(lifetime_minutes)} minutes."
    )
    return 0


def _format_minutes(minutes: float) -> str:
    """Render a minute count without a trailing `.0` for whole values.

    Lifetimes are whole minutes in practice, so `5` reads better than `5.0`; a
    fractional value still prints honestly.
    """
    return str(int(minutes)) if float(minutes).is_integer() else f"{minutes:g}"


def _deny(approvals: ApprovalStore, approval_id: str) -> int:
    if not approvals.deny(approval_id):
        print(f"bouncer: no parked call with id {approval_id}")
        return 1
    print(f"denied {approval_id}")
    return 0


def _reset(approvals: ApprovalStore, caller: str) -> int:
    cleared = approvals.reset(caller)
    print(f"reset {caller}: cleared {cleared} approved destructive action(s) from the window")
    return 0


def _log(audit: AuditLog, limit: int) -> int:
    entries = audit.entries(limit)
    if not entries:
        print("decision log is empty")
        return 0
    print(f"{'TIMESTAMP':<22}{'CALLER':<16}{'TOOL':<20}{'CLASS':<13}{'DECISION':<10}ARGS_HASH")
    for entry in entries:
        print(
            f"{entry.timestamp:<22}{entry.caller:<16}{entry.tool:<20}"
            f"{entry.classification:<13}{entry.decision:<10}{entry.args_hash[:16]}"
        )
    return 0


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


if __name__ == "__main__":
    raise SystemExit(main())
