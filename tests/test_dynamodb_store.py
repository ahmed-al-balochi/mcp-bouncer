"""DynamoDB-specific properties that the shared contract suite cannot express.

The parametrised suite in ``test_approvals.py`` proves the DynamoDB store honours
the same contract as SQLite (A8). These tests reach past the interface to assert
the *mechanism* the requirements name explicitly:

* the one-shot claim is a conditional delete that yields exactly one winner even
  when many callers race it (R27),
* expiry is refused at claim time by the condition itself, so a stale grant that
  TTL has not yet physically removed is still denied while its item is provably
  still in the table (R28),
* the rolling-window count is a key-range Query that stays correct as releases
  fall out of the window across the hour boundary (R14, R28).

All of it runs against a moto fake: no AWS credentials, no network (R45).
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
    """The whole point of the DynamoDB backend: one grant, one release, under a race.

    Eight threads claim the same grant at once. The conditional delete lets the
    single winner remove the item; every other thread gets ConditionalCheckFailed
    and returns False. Exactly one True, and the caller's window count is 1 -- the
    release was recorded once, not once per racer.
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
    """R28: expiry is enforced by the claim condition, not by trusting async TTL.

    The grant is left physically present -- no ``expire()`` sweep, no TTL deletion
    -- and the clock is wound past its TTL. ``consume`` must still refuse it,
    because the conditional delete carries ``expires_at > now``. We then read the
    item straight from the table to prove it was the condition that refused the
    claim, not a prior deletion: the stale item is provably still there.
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

    Releases are stored under PK=RELEASE#<caller> with the timestamp in the sort
    key. If the sort key were the timestamp alone, two grants claimed by one
    caller within the same clock tick would write the same PK and SK and the
    second PutItem would silently overwrite the first -- the window would count
    one, and a caller could slip past the destructive cap (R14). The sort key
    therefore carries the argument digest as well.

    The frozen clock makes the collision certain rather than unlikely, which is
    the only way to test it deterministically: with a real clock the two writes
    would land microseconds apart and pass either way.
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

    Two releases are recorded, then the clock advances so the first falls outside
    the hour while the second stays inside. The count must drop from two to one to
    zero as the window slides -- exactly the behaviour a Query with an ``SK >
    cutoff`` key-range condition produces, and never what a whole-table Scan would.
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
