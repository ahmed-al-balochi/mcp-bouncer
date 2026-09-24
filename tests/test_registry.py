"""The gate must refuse to boot on a policy it cannot fully validate."""

from __future__ import annotations

from pathlib import Path

import pytest

from gate.registry import PolicyConfigError, load_registry, parse_policy_yaml

VALID = """
defaults:
  unclassified: block
  annotations: escalate-only
limits:
  destructive_per_hour: 3
  approval_ttl_minutes: 10
tools:
  "wiki.read_page": read
  "wiki.*": write
actions:
  read: pass
  write: pass
  destructive: approve
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_shipped_policy_loads(policy_path: Path):
    registry = load_registry(policy_path)
    assert registry.patterns["wiki.delete_page"] == "destructive"
    assert registry.limits.destructive_per_hour == 3
    assert registry.limits.approval_ttl_minutes == 10
    assert registry.limits.actions["destructive"] == "approve"
    assert registry.limits.unclassified_action == "block"


def test_tool_order_is_preserved_so_globs_stay_predictable(tmp_path: Path):
    registry = load_registry(_write(tmp_path, VALID))
    assert list(registry.patterns) == ["wiki.read_page", "wiki.*"]


def test_comments_and_quoted_keys_are_handled():
    parsed = parse_policy_yaml('# leading\ntools:\n  "a.b#c": read  # trailing\n')
    assert parsed == {"tools": {"a.b#c": "read"}}


def test_missing_file_is_a_config_error(tmp_path: Path):
    with pytest.raises(PolicyConfigError):
        load_registry(tmp_path / "absent.yaml")


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(("unclassified: block", "unclassified: pass"), id="unclassified-not-block"),
        pytest.param(
            ("annotations: escalate-only", "annotations: trust"), id="annotations-trusted"
        ),
        pytest.param(("read: pass", "read: yolo"), id="unknown-action"),
        pytest.param(('"wiki.read_page": read', '"wiki.read_page": browse'), id="unknown-class"),
        pytest.param(
            ("approval_ttl_minutes: 10", "approval_ttl_minutes: 0"), id="zero-ttl"
        ),
        pytest.param(
            ("destructive_per_hour: 3", "destructive_per_hour: -1"), id="negative-cap"
        ),
        pytest.param(("limits:", "limitz:"), id="unknown-section"),
        pytest.param(("  read: pass\n", ""), id="missing-action-entry"),
        pytest.param(("  destructive_per_hour: 3\n", ""), id="missing-limit"),
    ],
)
def test_invalid_policies_refuse_to_boot(tmp_path: Path, mutation: tuple[str, str]):
    original, replacement = mutation
    assert original in VALID
    with pytest.raises(PolicyConfigError):
        load_registry(_write(tmp_path, VALID.replace(original, replacement)))


def test_the_action_table_is_configurable_within_the_known_decisions(tmp_path: Path):
    """`actions` is policy, not code: an operator may tighten destructive to block."""
    registry = load_registry(
        _write(tmp_path, VALID.replace("destructive: approve", "destructive: block"))
    )
    assert registry.limits.actions["destructive"] == "block"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("tools:\n\t\"a\": read\n", id="tab-indent"),
        pytest.param("tools:\n   a: read\n", id="odd-indent"),
        pytest.param("tools:\n  - a\n", id="list"),
        pytest.param("tools\n", id="no-colon"),
        pytest.param("tools:\n", id="empty-mapping"),
        pytest.param("a: 1\nb:\nc: 2\n", id="nested-key-without-children"),
        pytest.param("tools:\n  a: read\n  a: write\n", id="duplicate-key"),
        pytest.param("tools:\n  a: read\n   b: write\n", id="unexpected-indent"),
        pytest.param(": read\n", id="empty-key"),
    ],
)
def test_unsupported_yaml_is_rejected_rather_than_guessed_at(text: str):
    with pytest.raises(PolicyConfigError):
        parse_policy_yaml(text)


def test_scalars_are_parsed_without_a_yaml_library():
    parsed = parse_policy_yaml("a:\n  i: 3\n  b: true\n  n: null\n  s: hello\n  q: '7'\n")
    assert parsed == {"a": {"i": 3, "b": True, "n": None, "s": "hello", "q": "7"}}
