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


# --- backend parametrisation ---------------------------------------------
#
# Every behavioural store test runs once per backend. SQLite is the default the
# gate ships with (R30); the DynamoDB backend has to prove it satisfies the
# identical contract, not a lookalike (R26, A8), so the same assertions run
# against it through a moto fake. moto keeps the DynamoDB path entirely
# in-process: no AWS credentials, no network (R45). The dummy credentials below
# exist only so boto3 will construct a client at all -- moto never checks them.


@pytest.fixture(params=["sqlite", "dynamodb"])
def store_backend(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture(autouse=True)
def _moto_writes_are_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give moto's fake the per-write atomicity real DynamoDB has.

    DynamoDB evaluates a write's ConditionExpression and applies the write as one
    atomic step. moto does not: its ``delete_item`` reads the item, evaluates the
    condition, then deletes, with nothing held in between, so two threads can
    both pass the condition and both "win". That made the concurrent one-shot
    test flaky -- a fault in the fake, not in the store, and proven by widening
    the gap inside moto, which turned one winner into six.

    Serialising moto's write operations restores the property the store relies
    on without weakening the test: a store that claimed a grant by reading and
    then deleting unconditionally would still produce several winners, because
    the lock covers each single call, not the gap between two of them. The lock
    is re-entrant because a transaction applies its items through the same
    backend methods.

    Autouse, because several test modules build their own moto fixture and
    every one of them needs the same property; patching the class is inert
    for tests that never start moto.
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

    The fake is torn down with the test, so no state leaks between parametrised
    runs. Table names are unique per test for the same reason.

    The region is pinned for the duration of the test so the provisioning client
    here and the store's own boto3 client agree: any AWS_REGION inherited from
    the surrounding shell is overridden, then restored, so a table created in one
    region is never queried in another. moto ignores credentials, but boto3
    still needs a region to build a client.
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

    A builder rather than a fixed instance so a test that needs an injected
    clock can ask for one and still run against both backends: the point of the
    parametrisation is that the DynamoDB store honours the identical contract,
    including the testable-clock seam.
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
