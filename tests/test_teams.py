"""Per-team policy: overrides may only tighten, and any loosening refuses boot.
Each loosening route gets its own test so a regression names the
hole; tightening is also proven end-to-end in tests/test_identity_lifecycle.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gate.registry import PolicyConfigError, known_teams, load_registry

# A baseline with room to tighten in every direction: a write to promote, a
# cap and TTL to lower, an action to make stricter.
BASE = """
defaults:
  unclassified: block
  annotations: escalate-only
limits:
  destructive_per_hour: 3
  approval_ttl_minutes: 10
tools:
  "wiki.read_page": read
  "wiki.write_page": write
  "wiki.delete_page": destructive
actions:
  read: pass
  write: pass
  destructive: approve
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _with_team(block: str) -> str:
    return BASE + "teams:\n" + block


# A baseline whose tool list is a glob, so a team's exact-name entry would be
# matched by it rather than replacing a literal key. This is the shape that makes
# shadowing possible at all.
GLOB_BASE = """
defaults:
  unclassified: block
  annotations: escalate-only
limits:
  destructive_per_hour: 3
  approval_ttl_minutes: 10
tools:
  "wiki.delete_page": destructive
  "wiki.*": write
actions:
  read: pass
  write: pass
  destructive: approve
"""


# --- the shipped policy ---------------------------------------------------


def test_the_shipped_policy_defines_both_teams(policy_path: Path):
    registry = load_registry(policy_path)
    assert known_teams(registry) == frozenset({"CustomerChat", "DevChat"})


def test_customerchat_tightens_write_to_destructive_and_lowers_its_limits(
    policy_path: Path,
):
    registry = load_registry(policy_path)
    view = registry.for_team("CustomerChat")
    assert view.patterns["wiki.write_page"] == "destructive"
    assert view.limits.destructive_per_hour == 1
    assert view.limits.approval_ttl_minutes == 5
    # Deny-by-default is untouched by a team.
    assert view.limits.unclassified_action == "block"


def test_devchat_keeps_write_and_only_lowers_its_cap(policy_path: Path):
    registry = load_registry(policy_path)
    view = registry.for_team("DevChat")
    assert view.patterns["wiki.write_page"] == "write"
    assert view.limits.destructive_per_hour == 2
    # Not overridden, so it stays at the baseline.
    assert view.limits.approval_ttl_minutes == 10


# Glob shadowing is the subtlest loosening route: a team can weaken a tool via a
# broader glob that wins or a narrower exact name that beats a stricter glob. The
# registry blocks both by refusing any key the baseline does not already list.


def test_a_team_cannot_introduce_a_broader_glob_that_shadows_a_strict_tool(
    tmp_path: Path,
):
    """`wiki.*: write` alongside a baseline `wiki.delete_page: destructive`.
    Nothing lowers a stated value, so a severity check would pass it; the
    loosening is positional. Refused because the baseline does not list the key.
    """
    policy = _with_team('  DevChat:\n    tools:\n      "wiki.*": write\n')

    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "wiki.*" in str(error.value)


def test_a_team_cannot_add_an_exact_name_that_undercuts_a_stricter_glob(
    tmp_path: Path,
):
    """A baseline glob of `write` plus a team's exact `wiki.read_page: read`.
    The exact name outranks the glob, lowering wiki.read_page without editing the
    glob. Refused because the baseline does not list that key.
    """
    policy = (
        GLOB_BASE
        + 'teams:\n  DevChat:\n    tools:\n      "wiki.read_page": read\n'
    )

    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "wiki.read_page" in str(error.value)


def test_a_team_may_still_tighten_a_glob_the_baseline_itself_lists(tmp_path: Path):
    """The rule bites on introduction, not on tightening: a listed glob is fair game.
    Without this, the two tests above would be satisfied by a registry that
    banned every team tool override, making the feature useless.
    """
    policy = (
        GLOB_BASE
        + 'teams:\n  CustomerChat:\n    tools:\n      "wiki.*": destructive\n'
    )

    view = load_registry(_write(tmp_path, policy)).for_team("CustomerChat")
    assert view.patterns["wiki.*"] == "destructive"
    assert view.patterns["wiki.delete_page"] == "destructive"
    # Limits were not overridden, so they stay exactly at the baseline.
    assert view.limits.destructive_per_hour == 3
    assert view.limits.approval_ttl_minutes == 10


def test_an_unknown_team_falls_back_to_the_baseline(policy_path: Path):
    registry = load_registry(policy_path)
    baseline = registry.for_team(None)
    fallback = registry.for_team("NoSuchTeam")
    assert fallback.patterns == baseline.patterns
    assert fallback.limits.destructive_per_hour == baseline.limits.destructive_per_hour


# --- tightening is accepted ------------------------------------------------


def test_a_purely_tightening_team_loads(tmp_path: Path):
    policy = _with_team(
        "  Tight:\n"
        '    tools:\n      "wiki.write_page": destructive\n'
        "    actions:\n      write: approve\n"
        "    limits:\n      destructive_per_hour: 1\n      approval_ttl_minutes: 5\n"
    )
    registry = load_registry(_write(tmp_path, policy))
    view = registry.for_team("Tight")
    assert view.patterns["wiki.write_page"] == "destructive"
    assert view.limits.actions["write"] == "approve"
    assert view.limits.destructive_per_hour == 1
    assert view.limits.approval_ttl_minutes == 5


def test_a_team_may_hold_a_limit_at_the_baseline(tmp_path: Path):
    """Equal to the baseline is not looser, so it is allowed."""
    policy = _with_team("  Same:\n    limits:\n      destructive_per_hour: 3\n")
    registry = load_registry(_write(tmp_path, policy))
    assert registry.for_team("Same").limits.destructive_per_hour == 3


# --- one test per loosening route ------------------------------------


def test_loosening_a_classification_prevents_boot(tmp_path: Path):
    policy = _with_team(
        '  Bad:\n    tools:\n      "wiki.delete_page": write\n'
    )
    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "loosen" in str(error.value).lower()


def test_raising_the_destructive_cap_prevents_boot(tmp_path: Path):
    policy = _with_team("  Bad:\n    limits:\n      destructive_per_hour: 4\n")
    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "destructive_per_hour" in str(error.value)


def test_raising_the_ttl_prevents_boot(tmp_path: Path):
    policy = _with_team("  Bad:\n    limits:\n      approval_ttl_minutes: 20\n")
    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "approval_ttl_minutes" in str(error.value)


def test_loosening_an_action_prevents_boot(tmp_path: Path):
    """destructive: approve -> pass would let destructive calls straight through."""
    policy = _with_team("  Bad:\n    actions:\n      destructive: pass\n")
    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "loosen" in str(error.value).lower()


def test_introducing_an_unclassified_tool_prevents_boot(tmp_path: Path):
    """The subtle route: a team naming a tool the baseline does not classify
    turns a default-deny into an allow, so it must refuse to boot."""
    policy = _with_team(
        '  Bad:\n    tools:\n      "payments.refund": read\n'
    )
    with pytest.raises(PolicyConfigError) as error:
        load_registry(_write(tmp_path, policy))
    assert "payments.refund" in str(error.value)


def test_a_team_changing_the_unclassified_default_prevents_boot(tmp_path: Path):
    """A team must not touch defaults.unclassified; the schema forbids the key."""
    policy = _with_team("  Bad:\n    unclassified: pass\n")
    with pytest.raises(PolicyConfigError):
        load_registry(_write(tmp_path, policy))


def test_a_team_changing_the_annotations_default_prevents_boot(tmp_path: Path):
    """A team must not touch defaults.annotations; the schema forbids the key."""
    policy = _with_team("  Bad:\n    annotations: trust\n")
    with pytest.raises(PolicyConfigError):
        load_registry(_write(tmp_path, policy))


def test_an_unknown_key_in_a_team_block_prevents_boot(tmp_path: Path):
    policy = _with_team("  Bad:\n    limitz:\n      destructive_per_hour: 1\n")
    with pytest.raises(PolicyConfigError):
        load_registry(_write(tmp_path, policy))
