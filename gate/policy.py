"""Pure policy engine: what a tool call is, and what should happen to it.

This module has no I/O, no third-party imports and no global mutable state, so
every rule is unit-testable without mocks. Everything the rules need is passed in.
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

# MCP tool annotations are hints from the upstream server, which the gate does
# not trust. A hint can only raise the severity floor, never lower it, so
# `readOnlyHint: true` contributes no floor at all.
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

    An exact name in `registry` wins, else the first fnmatch pattern in order. A
    tool that matches nothing is `unknown` regardless of its annotations.
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

    Per-caller and per-team state arrive already resolved in `approval_state`
    and `limits`, so the engine performs no lookups and stays pure.
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
