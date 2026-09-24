"""Pure policy engine: what a tool call is, and what should happen to it.

This module has no I/O, no third-party imports and no global mutable state, so
every rule in it is unit-testable without mocks. Everything the rules need is
passed in.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal, Mapping

Classification = Literal["read", "write", "destructive", "unknown"]
Decision = Literal["pass", "block", "approve"]

UNKNOWN: Classification = "unknown"
PASS: Decision = "pass"
BLOCK: Decision = "block"
APPROVE: Decision = "approve"

_DECISIONS: frozenset[str] = frozenset({PASS, BLOCK, APPROVE})
_RANKED: tuple[Classification, ...] = ("read", "write", "destructive")
_SEVERITY: Mapping[str, int] = {name: rank for rank, name in enumerate(_RANKED)}

# MCP tool annotations are hints published by the upstream server, which the
# gate does not control and therefore does not trust. Each entry below reads
# "if this hint holds this value, the call is at least this severe". Because the
# hints can only raise the floor, a hint can escalate a classification but never
# soften one: `readOnlyHint: true` contributes no floor at all.
_ESCALATIONS: tuple[tuple[str, bool, Classification], ...] = (
    ("destructiveHint", True, "destructive"),
    ("readOnlyHint", False, "write"),
    ("idempotentHint", False, "write"),
)


@dataclass(frozen=True)
class ApprovalState:
    """What the approval store currently says about one pending call."""

    grant_available: bool = False
    approved_destructive_in_window: int = 0


@dataclass(frozen=True)
class Limits:
    """The tunables and action table from policy.yaml."""

    destructive_per_hour: int
    approval_ttl_minutes: int
    actions: Mapping[str, str]
    unclassified_action: str = BLOCK


def classify(
    tool_name: str,
    annotations: Mapping[str, Any],
    registry: Mapping[str, str],
) -> Classification:
    """Classify a tool call as read, write, destructive or unknown.

    An exact name in `registry` wins; otherwise the first fnmatch pattern in
    registry order wins. A tool that matches nothing is `unknown`, and stays
    unknown regardless of its annotations -- letting a hint promote an unlisted
    tool into a known class would turn a default-deny into a default-allow.
    """
    base = _match(tool_name, registry)
    if base is None:
        return UNKNOWN
    return _escalate(base, annotations)


def decide(
    classification: Classification,
    caller: str,
    approval_state: ApprovalState,
    limits: Limits,
) -> Decision:
    """Turn a classification into pass, block or approve (park).

    `caller` identifies who is calling. Per-caller state (the rolling
    destructive count) reaches this function already resolved, inside
    `approval_state`, and per-team rules reach it already resolved, inside
    `limits` and the `registry` passed to `classify`: the registry computes a
    team's tightened view at boot and the middleware hands the right view in.
    So identity is now real and it does shape the decision, but the engine still
    performs no lookups of its own -- it reads only its arguments, which is what
    keeps it pure (R16). `caller` stays in the signature because a decision is
    made on behalf of a caller and audited against one; a future per-caller rule
    that is still expressible as pure data would live here too.
    """
    if classification == UNKNOWN:
        return _sanitised(limits.unclassified_action)

    action = _sanitised(limits.actions.get(classification))
    if action != APPROVE:
        return action

    if approval_state.approved_destructive_in_window >= limits.destructive_per_hour:
        return BLOCK
    return PASS if approval_state.grant_available else APPROVE


def _match(tool_name: str, registry: Mapping[str, str]) -> Classification | None:
    exact = registry.get(tool_name)
    if exact in _SEVERITY:
        return exact  # type: ignore[return-value]
    for pattern, classification in registry.items():
        if classification in _SEVERITY and fnmatchcase(tool_name, pattern):
            return classification  # type: ignore[return-value]
    return None


def _escalate(base: Classification, annotations: Mapping[str, Any]) -> Classification:
    severity = _SEVERITY[base]
    for hint, trigger, floor in _ESCALATIONS:
        if annotations.get(hint) is trigger:
            severity = max(severity, _SEVERITY[floor])
    return _RANKED[severity]


def _sanitised(action: str | None) -> Decision:
    """Map anything the policy did not spell out correctly onto block."""
    return action if action in _DECISIONS else BLOCK  # type: ignore[return-value]
