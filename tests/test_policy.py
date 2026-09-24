"""Unit tests for the pure policy engine. No fixtures beyond plain data."""

from __future__ import annotations

from gate.policy import ApprovalState, Limits, classify, decide

PATTERNS = {
    "wiki.read_page": "read",
    "wiki.write_page": "write",
    "wiki.delete_page": "destructive",
    "wiki.*": "write",
}

LIMITS = Limits(
    destructive_per_hour=3,
    approval_ttl_minutes=10,
    actions={"read": "pass", "write": "pass", "destructive": "approve"},
)


def test_unmatched_tool_is_unknown_and_blocked():
    assert classify("payments.refund", {}, PATTERNS) == "unknown"
    assert decide("unknown", "agent-1", ApprovalState(), LIMITS) == "block"


def test_unknown_tool_cannot_be_rescued_by_annotations():
    """A hint must not promote an unlisted tool into a class the policy allows."""
    annotations = {"readOnlyHint": True, "destructiveHint": False}
    assert classify("payments.refund", annotations, PATTERNS) == "unknown"


def test_exact_name_wins_over_glob():
    assert classify("wiki.read_page", {}, PATTERNS) == "read"


def test_glob_matches_when_no_exact_entry_exists():
    assert classify("wiki.rename_page", {}, PATTERNS) == "write"


def test_destructive_hint_escalates_a_write():
    assert classify("wiki.write_page", {"destructiveHint": True}, PATTERNS) == "destructive"


def test_read_only_hint_false_escalates_a_read():
    assert classify("wiki.read_page", {"readOnlyHint": False}, PATTERNS) == "write"


def test_non_idempotent_hint_escalates_a_read():
    assert classify("wiki.read_page", {"idempotentHint": False}, PATTERNS) == "write"


def test_annotations_cannot_downgrade_a_destructive_tool():
    annotations = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
    assert classify("wiki.delete_page", annotations, PATTERNS) == "destructive"


def test_annotations_cannot_downgrade_a_write_tool():
    assert classify("wiki.write_page", {"readOnlyHint": True}, PATTERNS) == "write"


def test_missing_hints_leave_the_registry_classification_alone():
    annotations = {"readOnlyHint": None, "destructiveHint": None, "idempotentHint": None}
    assert classify("wiki.read_page", annotations, PATTERNS) == "read"


def test_each_class_maps_to_its_configured_action():
    assert decide("read", "agent-1", ApprovalState(), LIMITS) == "pass"
    assert decide("write", "agent-1", ApprovalState(), LIMITS) == "pass"
    assert decide("destructive", "agent-1", ApprovalState(), LIMITS) == "approve"


def test_destructive_passes_only_with_a_grant():
    state = ApprovalState(grant_available=True)
    assert decide("destructive", "agent-1", state, LIMITS) == "pass"


def test_rate_cap_trips_on_the_call_after_the_allowance():
    at_limit = ApprovalState(approved_destructive_in_window=3)
    assert decide("destructive", "agent-1", at_limit, LIMITS) == "block"

    under_limit = ApprovalState(approved_destructive_in_window=2)
    assert decide("destructive", "agent-1", under_limit, LIMITS) == "approve"


def test_rate_cap_beats_an_existing_grant():
    state = ApprovalState(grant_available=True, approved_destructive_in_window=3)
    assert decide("destructive", "agent-1", state, LIMITS) == "block"


def test_a_classification_with_no_action_configured_is_blocked():
    limits = Limits(
        destructive_per_hour=3,
        approval_ttl_minutes=10,
        actions={"read": "pass"},
    )
    assert decide("destructive", "agent-1", ApprovalState(), limits) == "block"


def test_a_nonsense_action_is_blocked():
    limits = Limits(
        destructive_per_hour=3,
        approval_ttl_minutes=10,
        actions={"read": "allow-everything"},
    )
    assert decide("read", "agent-1", ApprovalState(), limits) == "block"


def test_an_unclassified_action_other_than_block_is_still_blocked():
    limits = Limits(
        destructive_per_hour=3,
        approval_ttl_minutes=10,
        actions={"read": "pass", "write": "pass", "destructive": "approve"},
        unclassified_action="not-a-decision",
    )
    assert decide("unknown", "agent-1", ApprovalState(), limits) == "block"
