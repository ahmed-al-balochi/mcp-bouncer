"""DynamoDB-specific properties the shared contract suite cannot express.
These assert the mechanism directly: a one-shot conditional delete with one
winner, expiry refused at claim time, a key-range window Query.
"""

from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterator

import pytest

from tests.dynamodb_tables import create_approvals_table

CALLER = "agent-1"
TOOL = "wiki.delete_page"
PAGE_7 = {"title": "page-7"}


class _Clock:
    """A hand-cranked clock so TTL and window edges are hit exactly, not waited for."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def dynamodb_client() -> Iterator[Any]:
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
def make_store(dynamodb_client: Any) -> Callable[..., Any]:
    from gate.dynamodb_approvals import DynamoDBApprovalStore

    def build(*, clock: Callable[[], float] | None = None) -> Any:
        table = f"approvals-{uuid.uuid4().hex[:8]}"
        create_approvals_table(dynamodb_client, table)
        kwargs: dict[str, Any] = {"ttl_minutes": 10}
        if clock is not None:
            kwargs["clock"] = clock
        store = DynamoDBApprovalStore(table, **kwargs)
        # Stash the raw table name so a test can read an item back and prove a
        # mechanism (for example that an expired grant is still physically there).
        store._provisioning_table = table  # noqa: SLF001 - test-only handle
        return store

    return build


def test_concurrent_consume_produces_exactly_one_winner_on_dynamodb(
    make_store: Callable[..., Any]
):
    """One grant, one release, under a race: exactly one winner on DynamoDB.
    Eight threads claim the same grant. The conditional delete lets one win; the
    rest get ConditionalCheckFailed, so the window count is 1, not 8.
    """
    store = make_store()
    parked = store.create(CALLER, TOOL, PAGE_7)
    store.approve(parked.id)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.consume(CALLER, TOOL, PAGE_7), range(8)))

    assert results.count(True) == 1
    assert results.count(False) == 7
    assert store.approved_in_window(CALLER) == 1


def test_expired_grant_is_refused_while_its_item_still_physically_exists(
    make_store: Callable[..., Any], dynamodb_client: Any
):
    """Expiry is enforced by the claim condition, not by trusting async TTL.
    The grant is left physically present and the clock wound past its TTL; consume
    must still refuse it, and reading the item back proves the condition did it.
    """
    clock = _Clock()
    store = make_store(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7)
    store.approve(parked.id)

    from gate.approvals import args_hash

    digest = args_hash(CALLER, TOOL, PAGE_7)
    table = store._provisioning_table  # noqa: SLF001

    before = dynamodb_client.get_item(
        TableName=table, Key={"PK": {"S": f"GRANT#{digest}"}, "SK": {"S": "GRANT"}}
    )
    assert "Item" in before, "precondition: the grant item exists before it expires"

    clock.advance(10 * 60 + 1)
    assert store.consume(CALLER, TOOL, PAGE_7) is False

    after = dynamodb_client.get_item(
        TableName=table, Key={"PK": {"S": f"GRANT#{digest}"}, "SK": {"S": "GRANT"}}
    )
    assert "Item" in after, (
        "the condition, not TTL, refused the claim: the stale item is still present"
    )


def test_two_releases_in_the_same_clock_tick_are_both_counted(
    make_store: Callable[..., Any]
):
    """The rate cap must not be defeated by two releases sharing a timestamp.
    If the sort key were the timestamp alone they would overwrite and the window
    would undercount. The frozen clock makes the collision deterministic.
    """
    clock = _Clock()
    store = make_store(clock=clock)

    for title in ("first", "second"):
        parked = store.create(CALLER, TOOL, {"title": title})
        store.approve(parked.id)
        assert store.consume(CALLER, TOOL, {"title": title}) is True

    assert clock.now == 1_000_000.0, "precondition: the clock never moved"
    assert store.approved_in_window(CALLER) == 2


def test_window_query_is_correct_across_the_hour_boundary(
    make_store: Callable[..., Any]
):
    """approved_in_window counts only releases inside the rolling hour, via a key range.
    As the clock slides, two releases drop to one then zero, which a Query with an
    SK > cutoff condition produces and a whole-table Scan never would.
    """
    clock = _Clock()
    store = make_store(clock=clock)

    first = store.create(CALLER, TOOL, {"title": "first"})
    store.approve(first.id)
    assert store.consume(CALLER, TOOL, {"title": "first"}) is True

    clock.advance(1800)  # half an hour later
    second = store.create(CALLER, TOOL, {"title": "second"})
    store.approve(second.id)
    assert store.consume(CALLER, TOOL, {"title": "second"}) is True

    assert store.approved_in_window(CALLER) == 2

    # 31 minutes on: the first release (60 min old) is out; the second is in.
    clock.advance(1860)
    assert store.approved_in_window(CALLER) == 1

    # Another half hour: both releases are now older than an hour.
    clock.advance(1800)
    assert store.approved_in_window(CALLER) == 0


def test_native_ttl_attribute_matches_the_per_row_expiry(
    make_store: Callable[..., Any], dynamodb_client: Any
):
    """The grant's native `ttl` is computed from the per-row TTL.
    Park with a 5-minute TTL against a 10-minute store, approve, then read it.
    Both `expires_at` and `ttl` must be approve-time + 5 minutes, not + 10.
    """
    clock = _Clock()
    store = make_store(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=5 * 60.0)
    approve_time = clock.now
    store.approve(parked.id)

    from gate.approvals import args_hash

    digest = args_hash(CALLER, TOOL, PAGE_7)
    table = store._provisioning_table  # noqa: SLF001
    item = dynamodb_client.get_item(
        TableName=table, Key={"PK": {"S": f"GRANT#{digest}"}, "SK": {"S": "GRANT"}}
    )["Item"]

    assert float(item["expires_at"]["N"]) == approve_time + 5 * 60.0
    assert int(item["ttl"]["N"]) == int(approve_time + 5 * 60.0)
