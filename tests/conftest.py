from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from gate.approvals import ApprovalStore as SqliteApprovalStore
from gate.audit import AuditLog as SqliteAuditLog
from gate.registry import Registry, load_registry
from gate.storage import ApprovalStore, AuditLog

from tests.dynamodb_tables import create_approvals_table, create_audit_table

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"

# Type of the builder a test calls to get a store on the backend under test.
ApprovalStoreFactory = Callable[..., ApprovalStore]
AuditLogFactory = Callable[..., AuditLog]


@pytest.fixture
def policy_path() -> Path:
    return POLICY_PATH


@pytest.fixture
def registry() -> Registry:
    return load_registry(POLICY_PATH)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "gate.db"


# Every store test runs once per backend so the DynamoDB backend proves it
# satisfies the same contract as SQLite. moto fakes DynamoDB in-process, so the
# dummy credentials below exist only so boto3 will build a client.


@pytest.fixture(params=["sqlite", "dynamodb"])
def store_backend(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(autouse=True)
def _moto_writes_are_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serialise moto's writes so its fake has real DynamoDB's per-write atomicity.
    Without it the concurrent one-shot test is flaky: moto reads, checks, then
    deletes with nothing held, so two threads both win. The lock is re-entrant.
    """
    from moto.dynamodb.models import DynamoDBBackend

    lock = threading.RLock()
    for name in ("put_item", "update_item", "delete_item", "transact_write_items"):
        original = getattr(DynamoDBBackend, name)

        def serialised(*args: Any, _original: Any = original, **kwargs: Any) -> Any:
            with lock:
                return _original(*args, **kwargs)

        monkeypatch.setattr(DynamoDBBackend, name, serialised)


@pytest.fixture
def _dynamodb_client(store_backend: str) -> Iterator[Any]:
    """Yield a moto-faked DynamoDB client, or nothing for the SQLite backend.
    The region is pinned for the test so the provisioning client and the store's
    client agree, overriding any inherited AWS_REGION and restoring it after.
    """
    if store_backend != "dynamodb":
        yield None
        return

    region = "us-east-1"
    saved = {
        name: os.environ.get(name)
        for name in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
        )
    }
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_REGION"] = region
    os.environ["AWS_DEFAULT_REGION"] = region

    from moto import mock_aws
    import boto3

    try:
        with mock_aws():
            yield boto3.client("dynamodb", region_name=region)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture
def make_approvals(
    store_backend: str,
    db_path: Path,
    registry: Registry,
    _dynamodb_client: Any,
) -> ApprovalStoreFactory:
    """Return a builder for an approval store on the backend under test.
    A builder, not a fixed instance, so a test needing an injected clock can ask
    for one and still run against both backends.
    """
    ttl_minutes = registry.limits.approval_ttl_minutes

    def build(*, clock: Callable[[], float] | None = None) -> ApprovalStore:
        if store_backend == "sqlite":
            if clock is not None:
                return SqliteApprovalStore(db_path, ttl_minutes=ttl_minutes, clock=clock)
            return SqliteApprovalStore(db_path, ttl_minutes=ttl_minutes)

        from gate.dynamodb_approvals import DynamoDBApprovalStore

        table = f"approvals-{uuid.uuid4().hex[:8]}"
        create_approvals_table(_dynamodb_client, table)
        kwargs: dict[str, Any] = {"ttl_minutes": ttl_minutes}
        if clock is not None:
            kwargs["clock"] = clock
        return DynamoDBApprovalStore(table, **kwargs)

    return build


@pytest.fixture
def approvals(make_approvals: ApprovalStoreFactory) -> ApprovalStore:
    return make_approvals()


@pytest.fixture
def make_audit(
    store_backend: str,
    db_path: Path,
    _dynamodb_client: Any,
) -> AuditLogFactory:
    """Return a builder for an audit log on the backend under test."""

    def build(*, clock: Callable[[], float] | None = None) -> AuditLog:
        if store_backend == "sqlite":
            return SqliteAuditLog(db_path)

        from gate.dynamodb_audit import DynamoDBAuditLog

        table = f"audit-{uuid.uuid4().hex[:8]}"
        create_audit_table(_dynamodb_client, table)
        kwargs: dict[str, Any] = {}
        if clock is not None:
            kwargs["clock"] = clock
        return DynamoDBAuditLog(table, **kwargs)

    return build


@pytest.fixture
def audit(make_audit: AuditLogFactory) -> AuditLog:
    return make_audit()
