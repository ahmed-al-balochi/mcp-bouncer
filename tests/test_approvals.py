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


# Per-row (per-team) approval TTL. The store default is 10 minutes. A
# 5-minute per-row TTL stands in for a team that tightened its window. Each test
# advances the clock into the gap between the two to catch a grant that ignores it.

SHORT_TTL_SECONDS = 5 * 60.0  # a team-tightened 5 minutes; baseline is 10


def test_a_short_ttl_grant_cannot_be_consumed_past_its_own_ttl(make_approvals):
    """A 5-minute grant dies at 5 minutes, not at the 10-minute store default."""
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)
    store.approve(parked.id)

    clock.advance(SHORT_TTL_SECONDS + 1)  # 5 min + 1 s: past the team TTL
    assert store.consume(CALLER, TOOL, PAGE_7) is False


def test_a_short_ttl_grant_is_still_consumable_before_its_ttl(make_approvals):
    """Control: within the stamped 5 minutes the grant is still good."""
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)
    store.approve(parked.id)

    clock.advance(SHORT_TTL_SECONDS - 1)  # still inside the team window
    assert store.consume(CALLER, TOOL, PAGE_7) is True


def test_a_default_ttl_grant_still_lives_the_full_default(make_approvals):
    """Control: with no stamped TTL the grant lives the full store default, in
    the same gap the short-TTL grant dies in, proving the TTL is per-row."""
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7)  # no ttl_seconds => default
    store.approve(parked.id)

    clock.advance(SHORT_TTL_SECONDS + 1)  # past 5 min, before the 10-min default
    assert store.consume(CALLER, TOOL, PAGE_7) is True


def test_a_pending_row_with_a_short_ttl_expires_on_its_own_schedule(make_approvals):
    """expire() retires a short-TTL pending row at its own TTL, not the default."""
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)
    assert [record.id for record in store.list_pending()] == [parked.id]

    clock.advance(SHORT_TTL_SECONDS + 1)
    store.expire()
    assert store.list_pending() == []


def test_a_pending_row_with_a_short_ttl_survives_before_its_ttl(make_approvals):
    """Control: the short-TTL pending row is still there just before its TTL."""
    clock = _Clock()
    store = make_approvals(clock=clock)
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)

    clock.advance(SHORT_TTL_SECONDS - 1)
    store.expire()
    assert [record.id for record in store.list_pending()] == [parked.id]


def test_dedup_reuse_tightens_a_stored_ttl_but_never_loosens_it(make_approvals):
    """The dedup path keeps the stricter of the two TTLs and never loosens it:
    park at the default, then at 5 minutes, then the default again, and the
    reused row stays at 5 minutes."""
    clock = _Clock()
    store = make_approvals(clock=clock)

    first = store.create(CALLER, TOOL, PAGE_7)  # default TTL
    second = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)
    assert second.id == first.id  # reused, not a new row
    # A later looser (default) create must NOT widen it back.
    third = store.create(CALLER, TOOL, PAGE_7)
    assert third.id == first.id

    store.approve(first.id)
    clock.advance(SHORT_TTL_SECONDS + 1)  # past the tightened 5 min
    assert store.consume(CALLER, TOOL, PAGE_7) is False


def test_approve_reports_the_stamped_ttl_lifetime(make_approvals):
    """approve() returns the resolved grant lifetime so the CLI can print it: a
    stamped 5-minute TTL comes back as 300, an unstamped row as the default."""
    store = make_approvals()
    parked = store.create(CALLER, TOOL, PAGE_7, ttl_seconds=SHORT_TTL_SECONDS)
    granted = store.approve(parked.id)
    assert granted is not None
    assert granted.ttl_seconds == SHORT_TTL_SECONDS

    other = store.create(CALLER, TOOL, PAGE_8)  # default
    granted_default = store.approve(other.id)
    assert granted_default is not None
    assert granted_default.ttl_seconds == store.ttl_seconds


# SQLite schema migration for the new per-row TTL column. These reach past
# the shared contract to the SQLite backend because the migration is a SQLite
# concern (DynamoDB is schemaless), so they use SqliteApprovalStore directly.

import sqlite3

from gate.approvals import ApprovalStore as SqliteApprovalStore


def _legacy_pending_schema(path) -> None:
    """Create a `pending` table in the pre-TTL shape, as an old DB would have."""
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE pending (
                id          TEXT PRIMARY KEY,
                caller      TEXT NOT NULL,
                tool        TEXT NOT NULL,
                arguments   TEXT NOT NULL,
                args_hash   TEXT NOT NULL,
                created_at  REAL NOT NULL,
                state       TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def test_opening_a_pre_ttl_database_adds_the_column_idempotently(db_path):
    """The migration adds `ttl_seconds` to an old table, and re-opening is a no-op."""
    _legacy_pending_schema(db_path)

    SqliteApprovalStore(db_path, ttl_minutes=10)  # first open: migrates
    SqliteApprovalStore(db_path, ttl_minutes=10)  # second open: must be a no-op

    connection = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(pending)")}
    finally:
        connection.close()
    assert "ttl_seconds" in columns


def test_a_legacy_row_without_a_ttl_falls_back_to_the_store_default(db_path):
    """A pending row written before the migration (NULL ttl_seconds) uses the
    store default when approved, so it stays consumable in the gap a stamped
    short TTL would have died in."""
    clock = _Clock()
    store = SqliteApprovalStore(db_path, ttl_minutes=10, clock=clock)
    # Insert a legacy-style pending row directly, leaving ttl_seconds NULL.
    from gate.approvals import PENDING, args_hash, canonical_arguments

    digest = args_hash(CALLER, TOOL, PAGE_7)
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            "INSERT INTO pending (id, caller, tool, arguments, args_hash, created_at,"
            " state) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy0000001", CALLER, TOOL, canonical_arguments(PAGE_7), digest,
             clock.now, PENDING),
        )
        connection.commit()
    finally:
        connection.close()

    granted = store.approve("legacy0000001")
    assert granted is not None
    # No stamped TTL => the store default lifetime.
    assert granted.ttl_seconds == store.ttl_seconds
    clock.advance(SHORT_TTL_SECONDS + 1)  # past 5 min, before the 10-min default
    assert store.consume(CALLER, TOOL, PAGE_7) is True
