"""The selection seam: which backend the factory returns, and who actually calls it.
The factory was written and then never called, so BOUNCER_STORE=dynamodb was
silently ignored. These tests cover the mapping and the real entry points."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Iterator

import pytest

from gate import cli, server
from gate.approvals import ApprovalStore as SqliteApprovalStore
from gate.audit import AuditLog as SqliteAuditLog
from gate.middleware import GateMiddleware
from gate.storage import (
    DYNAMODB_AUDIT_TABLE_ENV,
    DYNAMODB_TABLE_ENV,
    STORE_ENV,
    ApprovalStore,
    AuditLog,
    build_approval_store,
    build_audit_log,
)

from tests.dynamodb_tables import create_approvals_table, create_audit_table

_AWS_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
)


@pytest.fixture
def dynamodb_backend(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """Select the DynamoDB backend with moto-faked tables that really exist.
    In-process only: moto intercepts boto3, so there are no credentials and no
    network. The dummy credentials just let boto3 build a client."""
    region = "us-east-1"
    saved = {name: os.environ.get(name) for name in _AWS_ENV}
    for name in _AWS_ENV:
        os.environ[name] = "testing"
    os.environ["AWS_REGION"] = region
    os.environ["AWS_DEFAULT_REGION"] = region

    from moto import mock_aws
    import boto3

    try:
        with mock_aws():
            client = boto3.client("dynamodb", region_name=region)
            approvals_table = f"approvals-{uuid.uuid4().hex[:8]}"
            audit_table = f"audit-{uuid.uuid4().hex[:8]}"
            create_approvals_table(client, approvals_table)
            create_audit_table(client, audit_table)

            monkeypatch.setenv(STORE_ENV, "dynamodb")
            monkeypatch.setenv(DYNAMODB_TABLE_ENV, approvals_table)
            monkeypatch.setenv(DYNAMODB_AUDIT_TABLE_ENV, audit_table)
            yield {"approvals": approvals_table, "audit": audit_table}
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _dynamodb_classes() -> tuple[type, type]:
    from gate.dynamodb_approvals import DynamoDBApprovalStore
    from gate.dynamodb_audit import DynamoDBAuditLog

    return DynamoDBApprovalStore, DynamoDBAuditLog


# --- what the factory returns --------------------------------------------


def test_the_default_backend_is_sqlite(
    monkeypatch: pytest.MonkeyPatch, db_path: Path
):
    """An unset variable must mean SQLite, so local runs stay offline."""
    monkeypatch.delenv(STORE_ENV, raising=False)

    assert isinstance(build_approval_store(db_path=db_path), SqliteApprovalStore)
    assert isinstance(build_audit_log(db_path=db_path), SqliteAuditLog)


@pytest.mark.parametrize("value", ["sqlite", "SQLite", "  sqlite  ", ""])
def test_sqlite_is_selected_however_it_is_spelled(
    monkeypatch: pytest.MonkeyPatch, db_path: Path, value: str
):
    monkeypatch.setenv(STORE_ENV, value)

    assert isinstance(build_approval_store(db_path=db_path), SqliteApprovalStore)
    assert isinstance(build_audit_log(db_path=db_path), SqliteAuditLog)


def test_dynamodb_is_selected_when_configured(dynamodb_backend: dict[str, str]):
    approval_class, audit_class = _dynamodb_classes()

    assert isinstance(build_approval_store(), approval_class)
    assert isinstance(build_audit_log(), audit_class)


def test_the_backend_name_tolerates_case_and_surrounding_space(
    dynamodb_backend: dict[str, str], monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(STORE_ENV, "  DynamoDB ")
    approval_class, _ = _dynamodb_classes()

    assert isinstance(build_approval_store(), approval_class)


def test_an_unknown_backend_refuses_rather_than_falling_back(
    monkeypatch: pytest.MonkeyPatch, db_path: Path
):
    """Falling back to SQLite on a typo would be the dangerous reading: the
    operator asked for a shared store and would silently get a local file."""
    monkeypatch.setenv(STORE_ENV, "postgres")

    with pytest.raises(ValueError) as error:
        build_approval_store(db_path=db_path)
    assert "postgres" in str(error.value)
    assert "sqlite" in str(error.value) and "dynamodb" in str(error.value)

    with pytest.raises(ValueError):
        build_audit_log(db_path=db_path)


def test_dynamodb_without_a_table_name_refuses_to_build(
    monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(STORE_ENV, "dynamodb")
    monkeypatch.delenv(DYNAMODB_TABLE_ENV, raising=False)

    with pytest.raises(ValueError) as error:
        build_approval_store()
    assert DYNAMODB_TABLE_ENV in str(error.value)


def test_dynamodb_audit_without_a_table_name_refuses_to_build(
    monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv(STORE_ENV, "dynamodb")
    monkeypatch.delenv(DYNAMODB_AUDIT_TABLE_ENV, raising=False)

    with pytest.raises(ValueError) as error:
        build_audit_log()
    assert DYNAMODB_AUDIT_TABLE_ENV in str(error.value)


def test_a_blank_table_name_is_treated_as_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(STORE_ENV, "dynamodb")
    monkeypatch.setenv(DYNAMODB_TABLE_ENV, "   ")

    with pytest.raises(ValueError):
        build_approval_store()


def test_both_backends_satisfy_the_declared_protocols(
    monkeypatch: pytest.MonkeyPatch, db_path: Path, dynamodb_backend: dict[str, str]
):
    """The Protocol is the contract, so assert against it. `runtime_checkable`
    only checks that methods exist, not their signatures, so this is a floor.
    The behavioural parity is proven in tests/test_approvals.py."""
    assert isinstance(build_approval_store(), ApprovalStore)
    assert isinstance(build_audit_log(), AuditLog)

    monkeypatch.setenv(STORE_ENV, "sqlite")
    assert isinstance(build_approval_store(db_path=db_path), ApprovalStore)
    assert isinstance(build_audit_log(db_path=db_path), AuditLog)


# --- who calls the factory -----------------------------------------------


def _captured_middleware(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Capture the stores `build_gate` hands to the middleware. Inspecting the
    constructor arguments keeps the test about the wiring, not the proxy's
    shape."""
    captured: dict[str, Any] = {}

    class _Capturing(GateMiddleware):
        def __init__(self, registry: Any, approvals: Any, audit: Any, *args: Any):
            captured["approvals"] = approvals
            captured["audit"] = audit
            super().__init__(registry, approvals, audit, *args)

    monkeypatch.setattr(server, "GateMiddleware", _Capturing)
    return captured


def test_build_gate_uses_the_sqlite_backend_by_default(
    monkeypatch: pytest.MonkeyPatch, db_path: Path, policy_path: Path
):
    from demo.wiki_server import build_server

    monkeypatch.delenv(STORE_ENV, raising=False)
    captured = _captured_middleware(monkeypatch)

    server.build_gate(build_server(), policy_path=policy_path, db_path=db_path)

    assert isinstance(captured["approvals"], SqliteApprovalStore)
    assert isinstance(captured["audit"], SqliteAuditLog)


def test_build_gate_uses_the_configured_backend(
    monkeypatch: pytest.MonkeyPatch, policy_path: Path, dynamodb_backend: dict[str, str]
):
    """The regression guard: the server must go through the factory. Before this,
    build_gate ignored the factory, so a DynamoDB-configured deployment ran on a
    per-task SQLite file and lost the cross-host one-shot guarantee."""
    from demo.wiki_server import build_server

    approval_class, audit_class = _dynamodb_classes()
    captured = _captured_middleware(monkeypatch)

    server.build_gate(build_server(), policy_path=policy_path)

    assert isinstance(captured["approvals"], approval_class)
    assert isinstance(captured["audit"], audit_class)


def test_the_cli_acts_on_the_configured_backend(
    monkeypatch: pytest.MonkeyPatch, policy_path: Path, dynamodb_backend: dict[str, str]
):
    """An operator approving from a laptop must reach the deployed store.
    A call parked directly in the DynamoDB table is visible to `bouncer list`
    and releasable by `bouncer approve` only if the CLI resolved that backend."""
    store = build_approval_store()
    parked = store.create("agent-1", "wiki.delete_page", {"title": "home"})

    assert cli.main(["--policy", str(policy_path), "list"]) == 0
    assert cli.main(["--policy", str(policy_path), "approve", parked.id]) == 0
    assert store.consume("agent-1", "wiki.delete_page", {"title": "home"}) is True


def test_the_cli_reports_a_bad_backend_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch, policy_path: Path, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv(STORE_ENV, "postgres")

    assert cli.main(["--policy", str(policy_path), "list"]) == 2
    assert "postgres" in capsys.readouterr().out


def test_the_cli_log_command_reports_a_missing_audit_table_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    policy_path: Path,
    dynamodb_backend: dict[str, str],
    capsys: pytest.CaptureFixture[str],
):
    """A half-configured backend must produce a message, not a traceback. `log`
    reads only the audit store, so it is the one command that can hit a missing
    audit table while the approvals table is present."""
    monkeypatch.delenv(DYNAMODB_AUDIT_TABLE_ENV, raising=False)

    assert cli.main(["--policy", str(policy_path), "log"]) == 2
    assert DYNAMODB_AUDIT_TABLE_ENV in capsys.readouterr().out


def test_the_cli_log_command_does_not_require_the_approvals_table(
    monkeypatch: pytest.MonkeyPatch,
    policy_path: Path,
    dynamodb_backend: dict[str, str],
):
    """`log` should not demand configuration for a store it never touches."""
    monkeypatch.delenv(DYNAMODB_TABLE_ENV, raising=False)

    assert cli.main(["--policy", str(policy_path), "log"]) == 0


@pytest.mark.parametrize("backend", ["sqlite", "dynamodb"])
def test_the_factory_passes_an_injected_clock_through(
    monkeypatch: pytest.MonkeyPatch,
    db_path: Path,
    dynamodb_backend: dict[str, str],
    backend: str,
):
    """The testable-clock seam has to survive the factory on either backend.
    Otherwise the clock keyword could be dropped for one backend and every
    time-dependent test would quietly measure the wall clock instead."""
    monkeypatch.setenv(STORE_ENV, backend)
    frozen = 1_234_567.0

    store = build_approval_store(db_path=db_path, clock=lambda: frozen)
    parked = store.create("agent-1", "wiki.delete_page", {"title": "home"})

    assert parked.created_at == frozen
