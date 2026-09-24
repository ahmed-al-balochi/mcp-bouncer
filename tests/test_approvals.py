"""A grant releases one call, once, for exactly the arguments it was granted for."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from gate.approvals import args_hash
from gate.storage import ApprovalStore

CALLER = "agent-1"
TOOL = "wiki.delete_page"
PAGE_7 = {"title": "page-7"}
PAGE_8 = {"title": "page-8"}


class _Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_argument_hash_is_order_independent_but_value_sensitive():
    assert args_hash(CALLER, TOOL, {"a": 1, "b": 2}) == args_hash(CALLER, TOOL, {"b": 2, "a": 1})
    assert args_hash(CALLER, TOOL, PAGE_7) != args_hash(CALLER, TOOL, PAGE_8)
    assert args_hash(CALLER, TOOL, PAGE_7) != args_hash("agent-2", TOOL, PAGE_7)
    assert args_hash(CALLER, TOOL, PAGE_7) != args_hash(CALLER, "wiki.read_page", PAGE_7)


def test_creating_the_same_parked_call_twice_reuses_one_row(approvals: ApprovalStore):
    first = approvals.create(CALLER, TOOL, PAGE_7)
    second = approvals.create(CALLER, TOOL, PAGE_7)
    assert first.id == second.id
    assert [record.id for record in approvals.list_pending()] == [first.id]


def test_a_grant_is_consumed_exactly_once(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    assert approvals.approve(parked.id) is not None
    assert approvals.consume(CALLER, TOOL, PAGE_7) is True
    assert approvals.consume(CALLER, TOOL, PAGE_7) is False


def test_concurrent_consumers_produce_exactly_one_winner(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    approvals.approve(parked.id)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: approvals.consume(CALLER, TOOL, PAGE_7), range(8))
        )

    assert results.count(True) == 1
    assert approvals.approved_in_window(CALLER) == 1


def test_consuming_without_an_approval_fails(approvals: ApprovalStore):
    approvals.create(CALLER, TOOL, PAGE_7)
    assert approvals.consume(CALLER, TOOL, PAGE_7) is False


def test_a_grant_does_not_release_different_arguments(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    approvals.approve(parked.id)
    assert approvals.consume(CALLER, TOOL, PAGE_8) is False
    assert approvals.consume(CALLER, TOOL, PAGE_7) is True


def test_a_grant_does_not_release_a_different_caller(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    approvals.approve(parked.id)
    assert approvals.consume("agent-2", TOOL, PAGE_7) is False


def test_an_expired_grant_does_not_release(make_approvals):
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7)
    store.approve(parked.id)

    clock.advance(10 * 60 + 1)
    assert store.consume(CALLER, TOOL, PAGE_7) is False


def test_expire_sweeps_stale_grants_and_parked_calls(make_approvals):
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7)
    store.approve(parked.id)

    clock.advance(10 * 60 + 1)
    assert store.expire() == 1
    assert store.list_pending() == []


def test_denied_calls_never_get_a_grant(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    assert approvals.deny(parked.id) is True
    assert approvals.approve(parked.id) is None
    assert approvals.consume(CALLER, TOOL, PAGE_7) is False
    assert approvals.list_pending() == []


def test_deny_and_approve_report_unknown_ids(approvals: ApprovalStore):
    assert approvals.deny("nope") is False
    assert approvals.approve("nope") is None


def test_reset_clears_the_rolling_destructive_count(approvals: ApprovalStore):
    for title in ("a", "b", "c"):
        parked = approvals.create(CALLER, TOOL, {"title": title})
        approvals.approve(parked.id)
        assert approvals.consume(CALLER, TOOL, {"title": title}) is True

    assert approvals.approved_in_window(CALLER) == 3
    assert approvals.reset(CALLER) == 3
    assert approvals.approved_in_window(CALLER) == 0


def test_the_rolling_window_is_per_caller(approvals: ApprovalStore):
    parked = approvals.create(CALLER, TOOL, PAGE_7)
    approvals.approve(parked.id)
    approvals.consume(CALLER, TOOL, PAGE_7)

    assert approvals.approved_in_window(CALLER) == 1
    assert approvals.approved_in_window("agent-2") == 0


def test_releases_outside_the_window_no_longer_count(make_approvals):
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7)
    store.approve(parked.id)
    store.consume(CALLER, TOOL, PAGE_7)

    assert store.approved_in_window(CALLER) == 1
    clock.advance(3601)
    assert store.approved_in_window(CALLER) == 0
