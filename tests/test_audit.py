"""The decision log records what happened, in order, and only ever grows."""

from __future__ import annotations

from gate.storage import AuditLog


def test_entries_are_returned_oldest_first_with_every_field(audit: AuditLog):
    audit.record("agent-1", "wiki.read_page", "read", "pass", "hash-a")
    audit.record("agent-1", "wiki.delete_page", "destructive", "approve", "hash-b")

    entries = audit.entries()
    assert [entry.tool for entry in entries] == ["wiki.read_page", "wiki.delete_page"]

    first = entries[0]
    assert (first.caller, first.classification, first.decision, first.args_hash) == (
        "agent-1",
        "read",
        "pass",
        "hash-a",
    )
    assert first.timestamp.endswith("+00:00")


def test_the_log_exposes_no_way_to_change_or_remove_an_entry(audit: AuditLog):
    # Append-only is structural on every backend: whichever concrete class is
    # under test must expose record and entries and nothing that rewrites or
    # removes history. (For DynamoDB this is backed by IAM in the deployed
    # system too, R29, but the class must not even offer the method.)
    mutators = {"update", "delete", "clear", "truncate", "remove"}
    assert mutators.isdisjoint(dir(type(audit)))
    assert audit.entries() == []


def test_limit_returns_the_most_recent_entries(audit: AuditLog):
    for index in range(5):
        audit.record("agent-1", f"tool-{index}", "read", "pass", "hash")

    assert [entry.tool for entry in audit.entries(limit=2)] == ["tool-3", "tool-4"]
